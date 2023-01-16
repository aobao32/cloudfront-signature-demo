# Cloudfront Signature Demo
CloudFront signature - signed url/signed cookie demo

## 部署方法：

### 1、准备工作

1）签署证书，分别获得Public Key和Prviate Key，然后上传Public Key到Amazon CloudFront，以获得KEYID。
2）在Amazon CloudFront上，把要保护的发布点设置为Private，然后选中对应的KEY ID。
3）搭建环境，签署文件，获得文件签名（用于URL请求地址栏或Cookie Value）

### 2、Singed-URL in python for 标准策略

在环境上安装`boto3`，安装`cryptography`，然后修改`sign.py`文件中的文件名、路径等，然后配置正确的AKSK即可运行程序。程序签署完毕获得signed-URL。

### 3、Signed-URL/Signed Cookie for 标准策略/定制策略 in PHP7

在环境上安装webserver+php环境，对外通过网页可访问。

- 访问`signed-url.php`，验证Signed-URL的标准策略/定制策略，并通过网页上的JS播放器验证签名地址正常

- 访问`signed-cookie-canned.php`，验证Signed Cookie的标准策略，可通过浏览器开发工具（按F12）查看当前网页的Cookie，点击文件链接即可播放

- 访问`signed-cookie-custom.php`，验证Signed Cookie的定制策略，可限制生效时间、客户端IP地址等额外参数，可通过浏览器开发工具（按F12）查看当前网页的Cookie，点击文件链接即可播放