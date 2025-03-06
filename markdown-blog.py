import mistune
import flask
import os
import datetime
import re
import argparse
import json
import hashlib
import threading
import git
import frontmatter
from collections import defaultdict
import codecs
from email.utils import format_datetime, parsedate
from urllib.parse import urlparse, urljoin
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64

# 日期格式转换过滤器
def format_rfc822_to_iso(value):
    """Convert RFC 822 date string to ISO 8601 format."""
    parsed_date = datetime.datetime(*parsedate(value)[:6])
    return parsed_date.strftime('%Y-%m-%d')
# flask 程序定义
app = flask.Flask(__name__,template_folder='templates', static_folder='assets', static_url_path='/static')
# 注册过滤器
app.jinja_env.filters['rfc822_to_iso'] = format_rfc822_to_iso
# 全局文件缓存
FILECACHE = {}
# 全局导航缓存
NAVCACHE = {}
# mimetypes，用于网页返回文件使用
MIMETYPES = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".bmp": "image/bmp",
    ".ico": "image/vnd.microsoft.icon"
}
# 全局配置参数
class Config:
    def __init__(self):
        self.md_dir = "blog"
        self.title = "My Blog"
        self.url = "http://127.0.0.1:10011"
        self.desc = "Markdown Blog"
        self.cache = 10
        self.gitalk = {
            "clientid": None,
            "clientsecret": None,
            "repo": None,
            "owner": None,
            "admin": None
        }
        self.analyzer = {
            "baidu": None,
            "google": None,
            "googlead": None
        }
        self.ignore = {
            "file": [],
            "path": []
        }
        self.file_ext = [
            '.png',
            '.jpg',
            '.jpeg',
            '.gif',
            '.bmp',
            '.ico'
        ]
        self.default_file = "首页"
        self.proxy = {
            "googlead": None,
            "googleay": None,
            "githubapi": None,
            "githubcors": None
        }
        self.git = {
            "url": None,
            "branch": "main",
            "username": None,
            "pat": None,
            "path": None,
            "interval": 300
        }
        self.copyright = ""
        self.icp = ""
# 全局配置变量
CONFIG = Config()
# 文件历史信息，维护文件创建时间和修改时间
FILE_HISTORY = defaultdict(lambda: {"created": None, "last_modified": None})
# 全局配置hash，用于判断配置文件是否更改
CONFIG_HASH = None
# 获取文件hash
def get_file_hash(path):
    if os.path.exists(path):
        with open(path, "rb") as f:
            hash_object = hashlib.sha256()
            hash_object.update(f.read())
            file_hash = hash_object.hexdigest()
            return file_hash
    else:
        return None
# 保存配置
def save_config(path):
    with open(path, "w") as f:
        f.write(json.dumps(CONFIG.__dict__, indent=4, ensure_ascii=False))
    CONFIG_HASH = get_file_hash(path)
# 加载配置
def load_config(path):
    if os.path.exists(path):
        with open(path) as f:
            CONFIG.__dict__.update(json.loads(f.read()))
    else:
        save_config(path)
        print("配置文件不存在，已在本地生成配置文件，请配置后启动。")
        os._exit(0)
# 文件修改监控
def watch_config(path,loop=False):
    global CONFIG_HASH
    file_hash = get_file_hash(path)
    if file_hash is not None and file_hash != CONFIG_HASH:
        load_config(path)
        CONFIG_HASH = file_hash
    if loop:
        # 延时启动新线程检测，这个时间暂时是定死的，后续可以考虑改为配置文件设置
        thread = threading.Timer(10, watch_config, args=(path,loop))
        thread.start()
# 文章类
class Article:
    title = ''
    html = ''
    expires = 0
    metadata = {}
    encrypted = False
    def __init__(self, title, html, metadata={}, encrypted=False, cache=0):
        self.title = title
        self.html = html
        self.metadata = metadata
        self.encrypted = encrypted
        if cache > 0:
            self.expires = datetime.datetime.now() + datetime.timedelta(seconds=cache)
# 单个导航类
class Nav:
    active = False
    link = ''
    showname = ''
    realname = ''
    isdir = False
    children = []
    created = None
    last_modified = None
    def __init__(self, showname, link, realname, children=[], isdir=False, last_modified=None, created = None):
        self.showname = showname
        self.realname = realname
        self.link = link
        self.isdir = isdir
        self.children = children
        self.last_modified = last_modified
        self.created = created
# 导航栏类
class Navs:
    expires = 0
    navs = []
    def __init__(self, navs):
        self.navs = navs
        if len(navs) > 0:
            self.expires = datetime.datetime.now() + datetime.timedelta(seconds=CONFIG.cache)
# 判断是否是被忽略的文件或文件夹
def is_ignored(file):
    if os.path.exists(file):
        if os.path.isfile(file):
            basename = os.path.basename(file)
            for rule in CONFIG.ignore.get("file"):
                # 如果规则是以r::开头，就用正则进行匹配
                if rule.startswith("r::"):
                    # 正则匹配
                    if re.match(rule[3:], basename):
                        return True
                else:
                    # 直接匹配
                    if rule == basename:
                        return True
        else:
            for rule in CONFIG.ignore.get("path"):
                if rule.startswith("r::"):
                    # 正则匹配
                    if re.match(rule[3:], file):
                        return True
                else:
                    # 直接匹配
                    if rule == file:
                        return True
    return False
# 获取导航
def get_nav(path, prefix):
    isfile = os.path.isfile(path)
    isdir = os.path.isdir(path)
    if is_ignored(path):
        return None
    basename = os.path.basename(path)
    if isfile:
        # 这一段逻辑可能有点混乱，其实就是取值之后需要做不同的处理
        # file_parse 是用来分割提取扩展名
        file_parse = os.path.splitext(basename)
        # showname 需要提取@符号之后的内容，而且不能带后缀.md
        showname = file_parse[0].split('@')
        if len(showname) > 1:
            showname = showname[1]
        else:
            showname = showname[0]
        ext = file_parse[1]
        if ext != '.md':
            return None
        # 去除md_dir后的路径
        link = prefix + file_parse[0]
        if FILE_HISTORY.get(path,None) is not None:
            last_modified = FILE_HISTORY.get(path,None).get("last_modified",None)
            created = FILE_HISTORY.get(path,None).get("created",None)
        else:
            last_modified = datetime.datetime.fromtimestamp(os.path.getmtime(path))
            created = datetime.datetime.fromtimestamp(os.path.getctime(path))
        created = format_datetime(created)
        last_modified = format_datetime(last_modified)
        # app.logger.info(f"{path} created on {created}, last_modified: {last_modified}")
        return Nav(showname=showname, link=link, realname=basename, created=created, last_modified=last_modified)
    if isdir:
        showname = basename.split('@')
        if len(showname) > 1:
            showname = showname[1]
        else:
            showname = showname[0]
        prefix = os.path.join(prefix, basename) + '/'
        # 如果是目录会遍历目录下的文件进行递归
        navs = []
        for file in os.listdir(path):
            nav = get_nav(path=os.path.join(path, file), prefix=prefix)
            if nav:
                navs.append(nav)
        if len(navs) > 0:
            # navs进行排序，排序规则是先判断realname中是否包含@，如果包含就按照@进行分割，[0]的内容作为排序依据，如果不包含@，则优先级最低，不包含的所有nav通过realname排序放在所有nav的最后
            has_key_navs = []
            normal_navs = []
            for i in range(len(navs)):
                if '@' in navs[i].realname:
                    has_key_navs.append(navs[i])
                else:
                    normal_navs.append(navs[i])
            
            has_key_navs = sorted(has_key_navs, key=lambda x: x.realname.split('@')[0])
            normal_navs = sorted(normal_navs, key=lambda x: x.realname)
            navs = has_key_navs + normal_navs
            return Nav(showname=showname, link=prefix, realname=basename , isdir=True, children=navs)
        else:
            return None
# 获取完整导航
def get_navs():
    # NAVCACHE 会做一个全局缓存
    navs = NAVCACHE.get(CONFIG.md_dir, None)
    if navs and navs.expires > datetime.datetime.now():
        return navs.navs
    else:
        # 这里其实是有点多余，其实可以考虑直接变为对md_dir的get_nav，但是需要考虑顶端prefix的设置，可能会导致导航的link有问题
        # TODO: 简化逻辑
        navs = []
        path = CONFIG.md_dir
        prefix = '/'
        for file in os.listdir(path):
            nav = get_nav(path=os.path.join(path, file), prefix=prefix)
            if nav:
                navs.append(nav)
        has_key_navs = []
        normal_navs = []
        for i in range(len(navs)):
            if '@' in navs[i].realname:
                has_key_navs.append(navs[i])
            else:
                normal_navs.append(navs[i])
        
        has_key_navs = sorted(has_key_navs, key=lambda x: x.realname.split('@')[0])
        normal_navs = sorted(normal_navs, key=lambda x: x.realname)
        navs = has_key_navs + normal_navs
        NAVCACHE[CONFIG.md_dir] = Navs(navs)
        return navs
# 处理导航，命中当前阅读文章
def handle_nav(navs,path):
    for i in range(len(navs)):
        if navs[i].link == path:
            navs[i].active = True
        else:
            navs[i].active = False
        if navs[i].isdir:
            navs[i].children = handle_nav(navs[i].children,path)
    return navs
# 错误页面处理
def error_code(code):
    html_file = '404.html'
    if code == 500:
        html_file = '500.html'
    return flask.send_from_directory(os.path.join(app.root_path, 'templates'), html_file, mimetype='text/html')

class ImgHandleRenderer(mistune.HTMLRenderer):
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
    def image(self, alt, url, title=None):
        # 检查url是否是相对路径
        parsed = urlparse(url)
        if not parsed.netloc:
            # 没有域名部分，说明是相对路径，我们要转换它
            url = urljoin(self.base_url, url.lstrip('./'))
        # 然后调用原始HTMLRenderer的image方法
        return super().image(alt, url, title)
# 获取md文件html代码
def get_md_html(path):
    file_path = os.path.join(CONFIG.md_dir, path + '.md')
    if os.path.exists(file_path) and not is_ignored(file_path) and not is_ignored(os.path.dirname(file_path)):
        # 先从cache获取
        article = FILECACHE.get(file_path, None)
        if article and article.expires > datetime.datetime.now():
            pass
        else:
            # 使用 frontmatter 解析 markdown 文件
            post = frontmatter.load(file_path)
            metadata = post.metadata
            md_text = post.content
            
            base_url = urljoin(CONFIG.url, os.path.dirname(file_path).lstrip(CONFIG.md_dir)) + '/'
            html_text = mistune.markdown(md_text, escape=True, renderer=ImgHandleRenderer(base_url), plugins=('strikethrough', 'footnotes', 'table','speedup'))
            
            # 取文件名为默认title，如果metadata中有title则使用metadata中的
            title = os.path.splitext(os.path.basename(file_path))[0]
            if "@" in title:
                title = title.split("@")[1]
            if 'title' in metadata:
                title = metadata['title']
            
            # 检查是否需要加密
            encrypted = False
            if metadata.get('encrypted', False):
                # 生成随机的初始化向量（IV）
                iv = os.urandom(12)  # AES-GCM 使用 12 字节的 IV
                # 使用密码生成加密密钥
                password = metadata.get('password', '')
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=b'fixed_salt_for_blog',  # 使用固定的盐值
                    iterations=100000,
                )
                key = kdf.derive(password.encode())
                
                # 使用 AES-GCM 加密
                aesgcm = AESGCM(key)
                encrypted_data = aesgcm.encrypt(iv, html_text.encode(), None)
                
                # 将 IV 和加密数据组合并进行 base64 编码
                combined_data = iv + encrypted_data
                html_text = base64.b64encode(combined_data).decode()
                encrypted = True
                
            article = Article(title=title, html=html_text, metadata=metadata, encrypted=encrypted, cache=CONFIG.cache)
            FILECACHE[file_path] = article
            
        navs = get_navs()
        navs = handle_nav(navs,'/' + path)
        allnavs = get_all_nav(navs)
        navigations = []
        for nav in allnavs:
            navigations.append({
                'showname': nav.showname,
                'link': nav.link
            })
        CONFIG.gitalk['id'] = hashlib.md5(path.encode('utf-8')).hexdigest()
        return flask.render_template('layout.html',config=CONFIG, article=article, navs=navs, navigations=navigations)
    else:
        return error_code(404)
# 获取文件
def get_file(path):
    file_path = os.path.join(CONFIG.md_dir, path)
    ext = os.path.splitext(os.path.basename(file_path))[1]
    if os.path.exists(file_path):
        return flask.send_from_directory(os.path.join(app.root_path, CONFIG.md_dir), path, mimetype=MIMETYPES.get(ext,'text/html'))
    else:
        return error_code(404)
# 获取所有文件信息
def get_all_nav(navs):
    all_navs = []
    for i in range(len(navs)):
        if navs[i].isdir:
            all_navs = all_navs + get_all_nav(navs[i].children)
        else:
            all_navs.append(navs[i])
    return all_navs
# 获取rss
def ge_rss():
    navs_original = get_navs()
    navs = get_all_nav(navs_original)
    navs = sorted(navs, key=lambda nav: nav.created, reverse=True)
    return flask.render_template('rss.xml',title=CONFIG.title, url=CONFIG.url, desc=CONFIG.desc ,navs=navs)
# 获取sitemap
def ge_sitemap():
    navs_original = get_navs()
    navs = get_all_nav(navs_original)
    return flask.render_template('sitemap.xml',url=CONFIG.url, navs=navs)
# 拉取仓库
def pull_repo():
    # 使用github的PAT对指定仓库分支进行拉取
    repo_url = CONFIG.git["url"]
    repo_branch = CONFIG.git["branch"]
    repo_path = CONFIG.git["path"]
    username = CONFIG.git["username"]
    pat_token = CONFIG.git["pat"]
    interval = CONFIG.git["interval"]
    if repo_path == None or repo_path == "":
        repo_path = CONFIG.md_dir
    if repo_url and repo_branch and repo_path:
        pull_url = repo_url.replace("github.com", username + ":" + pat_token + "@" + "github.com")
        if not os.path.exists(repo_path):
            print("Cloning repository...")
            try:
                # 使用用户名密码连接
                repo = git.Repo.clone_from(pull_url, repo_path, branch=repo_branch)
                file_history()
            except Exception as ex:
                print(f"Cloning repository failed, ex:{ex}")
                return
            print("Repository cloned.")
        else:
            try:
                repo = git.Repo(repo_path)
            except Exception as ex:
                print(f"目录文件夹存在且打开仓库失败, ex:{ex}")
                return
            # 判断一下是否是当前配置的repo url
            if repo.remotes.origin.url != repo_url and repo.remotes.origin.url != pull_url:
                print(f"Current repository is not {repo_url}, is {repo.remotes.origin.url}")
                return
            else:
                try:
                    current = repo.head.commit
                    print("Updating repository...")
                    if repo.remotes.origin.url != pull_url:
                        repo.remotes.origin.set_url(pull_url)
                    repo.remotes.origin.pull(repo_branch)
                    # 判断是否更新内容
                    if current != repo.head.commit:
                        file_history()
                        print("Repository updated.")
                    else:
                        if FILE_HISTORY == {}:
                            file_history()
                        print("Repository is up to date.")
                except Exception as ex:
                    print(f"仓库更新失败, ex:{ex}")
        thread = threading.Timer(interval, pull_repo)
        thread.start()
    else:
        print("Please configure git repository.")
# 维护文件时间信息
def file_history():
    # 通过遍历文件的commit信息，维护文件的创建时间和修改时间，当代码量增大后此方法可能会占用非常大的资源
    repo_path = CONFIG.git["path"]
    if repo_path == None or repo_path == "":
        repo_path = CONFIG.md_dir
    repo = git.Repo(repo_path)
    # 遍历所有提交
    for commit in repo.iter_commits():
        for file in commit.stats.files:
            if file.startswith("\"") and file.endswith("\""):
                file = file[1:-1]
            try:
                # 将八进制字符串解码为二进制，然后解码为utf-8格式
                decoded_file = repo_path + "/" + codecs.escape_decode(file)[0].decode('utf-8')
            except:
                decoded_file = repo_path + "/" + file
            # 如果是第一次看到这个文件，则记录为创建时间
            if FILE_HISTORY[decoded_file]["created"] is None:
                FILE_HISTORY[decoded_file]["created"] = commit.authored_datetime
            # 更新文件的最后修改时间
            FILE_HISTORY[decoded_file]["last_modified"] = commit.authored_datetime
    app.logger.info("更新文件历史信息完成")
    # app.logger.info(FILE_HISTORY)

if __name__ == '__main__':
    # 解析命令行
     # 解析启动命令
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', type=str, default='127.0.0.1', help="initial host, default is 127.0.0.1")
    parser.add_argument('--port', type=int, default=10011, help="initial port, default is 10011")
    parser.add_argument('--debug', action='store_true', default=False, help="debug output")
    parser.add_argument('--config', type=str, default='config.json', help="config file path, default is config.json")
    args = parser.parse_args()
    load_config(args.config)
    if not args.debug:
        watch_config(args.config,loop=True)
    pull_repo()
    @app.route('/<path:subpath>', methods=['GET'])
    def view(subpath):
        if subpath == "favicon.ico":
            return flask.send_from_directory(os.path.join(app.root_path, 'assets'), 'favicon.ico', mimetype='image/vnd.microsoft.icon')
        if subpath == "rss.xml":
            return ge_rss()
        if subpath == "sitemap.xml":
            return ge_sitemap()
        ext = os.path.splitext(os.path.basename(subpath))[1]
        if ext in CONFIG.file_ext:
            return get_file(path=subpath)
        return get_md_html(subpath)
    
    @app.route('/', methods=['GET'])
    def index():
        # 跳转到默认网页
        return flask.redirect("/" + CONFIG.default_file)
    
    @app.errorhandler(404)
    def page_not_found(e):
        return error_code(404)
    
    @app.errorhandler(500)
    def internal_server_error(e):
        return error_code(500)
    
    app.run(host=args.host,port=args.port,debug=args.debug)