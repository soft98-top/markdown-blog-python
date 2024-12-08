# markdown-blog-python

a simple blog for markdown file

## 简介

此项目是对于`@gaowei-space/markdown-blog`项目的复刻，出发点主要是因为自己想增添一些功能，但实在是对于go语言不擅长，所以只能用python进行复刻，如果大家喜欢go语言程序，请移步原项目进行下载使用。

## 功能

复刻功能

- 将指定目录下的markdown文件渲染成网页进行显示
- 可以使用`@`符号前的序号对文件进行排序
- 支持文件访问，出于安全考虑，只显示图片
- 支持三方统计、备案号、评论等原有功能，详情参考原项目

新增功能

- 谷歌分析、谷歌广告、github的反代设置
- 配置git仓库自动拉取最新文件（目前仅支持gihub使用pat进行拉取）
- rss/sitemap文件
- 配置热更新
- 导航栏文章名称搜索
- md文件渲染时图片链接相对路径转域名路径（方便rss阅读器加载）

TODO

- 支持加密文件访问

## 使用方法

```
# 下载文件到本地
git clone https://github.com/soft98-top/markdown-blog-python.git
# 安装依赖文件
pip3 install -r requirements.txt
# 修改配置文件
# 启动项目
python3 markdown-blog.py
```

监听地址和端口设置

`python3 markdown-blog --host 127.0.0.1 --port 10011`

配置说明

```
{
    "md_dir": "blog", // md文件目录
    "title": "My Blog", // 网站标题
    "url": "http://127.0.0.1:10011", // 域名地址，用于生成rss/sitemap和转换图片链接
    "desc": "Markdown Blog", // 网站描述
    "cache": 10, // 网页缓存时间，以秒为单位
    "gitalk": { // gitalk评论相关设置
        "clientid": null,
        "clientsecret": null,
        "repo": null,
        "owner": null,
        "admin": null
    },
    "analyzer": { // 三方分析平台设置
        "baidu": null,
        "google": null,
        "googlead": null
    },
    "ignore": { // 忽略文件和文件夹设置
        "file": [],
        "path": []
    },
    "file_ext": [ // 允许访问的后缀名
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".bmp",
        ".ico"
    ],
    "default_file": "首页", // 默认访问文件，即直接访问域名会跳转的页面
    "proxy": { // 反代设置，用于解决墙内网络无法评论等问题
        "googlead": null,
        "googleay": null,
        "githubapi": null,
        "githubcors": null
    },
    "git": { // git仓库设置，当使用github仓库同步备份md文件时，用此设置定时拉取文件
        "url": null,
        "branch": "main",
        "username": null,
        "pat": null,
        "path": null,
        "interval": 300
    },
    "copyright":"", // 版权所属
    "icp":"" // icp备案号
}
```

## 问题

- 没有对Windows做兼容，代码中部分直接添加的符号可能会导致在Windows上无法运行
- 没有详尽的调试信息，可能会出现意外的情况无法处理
- 程序使用的mistune是v3.0.2版本，对python版本有要求，实测python3.6无法安装，开发使用版本为python3.9.6

## 鸣谢

[gaowei-space/markdown-blog](https://github.com/gaowei-space/markdown-blog)