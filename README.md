# RSA-AES-encrypt
RSA和AES的加验签和加解密demo，可用于敏感数据的请求签名和加密，针对不同项目最好使用不同的加密方式，此demo仅用做参考。
## Web 前端密码加密是否有意义？
之前在v2ex看到过大家的讨论，反正各有各的说法，后来在知乎也看到了一样的讨论，其中有个大佬的回复让我印象很深：*** 既然市面上大部分锁都可以在20分钟内撬开，那门上装锁是否还有意义？ *** 这个比喻很形象了，如果对数据传输的安全有要求的话，有加密总比没有要强把...
## demo演示
![demo](https://img.lanhongjin.com/encrypt_demo.gif "demo")
[preview][5]
## RSA公私钥说明
*非对称加密算法需要两个密钥：公开密钥（publickey:简称公钥）和私有密钥（privatekey:简称私钥）。公钥与私钥是一对，如果用公钥对数据进行加密，只有用对应的私钥才能解密。* RSA是最常用的非对称加密算法。

客户端和服务端分别持有自己的私钥，交换公钥。公钥用于参数加密及签名验签，私钥用于参数解密及签名加签。
## 项目依赖
AES加密及md5散列： [crypto.js][1] 
RSA加密： [jsencrypt][2]
RSA密钥对生成：[http://web.chacuo.net/netrsakeypair/][3]
## 参数说明
数据加密前的原始数据：
```javascript
{
	sequenceNo: this.getGuid(), // 流水号
	version: '1.1', // 项目版本号
	timestamp: new Date().getTime(), // 时间戳
	signature: '', // 签名
	// AES随机key及iv组成的json字符串 使用 RSA 加密后的密文
	encryptedKey: '',
	// encryptedData 为以下JSON格式的加密数据
	encryptedData: {
		head: {
			// 设备唯一标识符
			deviceID: '',
			...
		},
		// 业务请求参数
		body: {...}
	}
}
```
## 参数加密
** 生成 encryptedKey 和 encryptedData **
```javascript
getEncryptedData() {
	// origin data before encrypt
	const baseData = {
		head: {
		...this.options.encryptedData.head
		},
		body: {
		...this.options.encryptedData.body
		}
	}
	// 1. 随机生成AES密钥key(128位，base64编码)，向量iv(16位)
	const aesKey = AES.createAesKey();
	const iv = AES.createAesIv();
	// 2. 使用key和iv对未加密的encryptedData的json字符串进行AES加密，得到encryptedData
	// encryptedData：
	const encryptedData = AES.encryptAES(baseData, aesKey, iv)
	// 3.将key和iv组成的json字符串进行RSA公钥加密
	// encryptedKey：
	const objMap = {
		key: aesKey,
		iv: iv
	}
	// @bug RSA.publicEncrypt提示message too long...
	// @resolve: https://stackoverflow.com/questions/15206594/rsa-message-too-long-javascript-jsbn
	// 提示message过长跟生成密钥位数有关，1024位密钥在没有填充的情况下只能加密117个字节，2048位可以加密245，4096位可以加密501个字节
	const encryptedKey = RSA.publicEncrypt(JSON.stringify(objMap))
	return {
		encryptedKey,
		encryptedData
	}
}
```
## 签名
```javascript
sign(signData) {
	// 1.将加密前的encryptedData的json字符串进行md5操作，
	// 2.再将报文中timestamp等字段以key=value的形式按照key名称进行升序排序，并以&拼接字符串
	// 3.将拼接后的字符串进行RSA私钥加密后得到signature签名字段
	// 注意前后端加签验签的字段是否一致的
	const obj = {
		encryptedData: MD5(JSON.stringify(this.options.encryptedData)),
		sequenceNo: this.options.sequenceNo,
		timestamp: this.options.timestamp,
		version: this.options.version
	}
	const data = signData || obj;
	const str = RSA.getKeyVal(data);
	return RSA.privateEncrypt(str)
}
```
## 数据解密
```javascript
/**
* 解密数据
* @param {String} key 加密的encryptedKey
* @param {String} data 加密的encryptedData
* @return {String} 未加密的encryptedData的json字符串
* **/
getDecryptedData(key, data) {
	// 响应报文解密步骤:
	// 1. 使用RSA私钥对encryptedKey进行解密，得到解密后的json字符串，再解析成对象后得到key、iv的的值
	const decryptKey = RSA.privateDecrypt(key)
	const objMap = JSON.parse(decryptKey)
	// 2. 使用key和iv对encryptedData进行AES解密，得到未加密的encryptedData的json字符串
	return AES.decryptAES(data, objMap.key, objMap.iv);
}
```
## 验签
```javascript
// 验签步骤: 
// 1.将解密后的encryptedData的json字符串进行md5操作
// 2.再将报文中timestamp等字段以key=value的形式按照key名称进行升序排序，并以&拼接字符串为字符串a
// 3.将signature使用RSA公钥解密得到明文字符串b，对比a与b是否相等。
// 注意前后端加签验签的字段是否一致的
/**
* 是否通过签名
* **/
isPass(signData, signature) {
	const data = {
	encryptedData: MD5(this.decrypted),
	sequenceNo: signData.sequenceNo,
	timestamp: signData.timestamp,
	version: signData.version
	}
	// 响应报文的明文签名
	const responseSign = RSA.getKeyVal(data);
	// 解密后的明文签名
	const decryptSign = RSA.publicDecrypt(signature);
	// console.log(decryptSign)
	return responseSign === decryptSign
}
```
实际开发情况，在响应拦截器下验证签名并通过之后前端就可以正常使用解密后的数据了。
## 其他
AES加密文档：[cryptojs文档][4]

遇到的问题：
* RSA公钥加密的时候报错`Message too long`，提示message过长跟生成密钥位数有关，1024位密钥在没有填充的情况下只能加密117个字节，2048位可以加密245，4096位可以加密501个字节，参考：https://stackoverflow.com/questions/15206594/rsa-message-too-long-javascript-jsbn][6]


现在vue的脚手架的配置文件没有在根目录了，而是直接放在了node_modules包内，刚刚上传demo到主机遇到了文件引入路径不对的问题，需要将node_modules/@vue/cli-service/lib/options.js下的publicPath路径改为'./'再重新打包。


[1]: https://www.npmjs.com/package/crypto-js "crypto.js"
[2]: https://www.npmjs.com/package/jsencrypt?activeTab=versions "jsencrypt"
[3]: http://web.chacuo.net/netrsakeypair/ "http://web.chacuo.net/netrsakeypair/"
[4]: https://cryptojs.gitbook.io/docs/ "cryptojs文档"
[5]: https://lanhongjin.com/encrypt "preview"
[6]: https://stackoverflow.com/questions/15206594/rsa-message-too-long-javascript-jsbn "https://stackoverflow.com/questions/15206594/rsa-message-too-long-javascript-jsbn"
