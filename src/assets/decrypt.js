import AES from './AES.js'
import RSA from './RSA.js'
import MD5 from 'crypto-js/md5';

export default class Decrypt {
	constructor(encryptedKey, encryptedData) {
		// 对encryptedKey和encryptedData解密，获取加密前数据
		this.decrypted = this.getDecryptedData(encryptedKey, encryptedData)
	}

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
			clientID: signData.clientID,
			sequenceNo: signData.sequenceNo,
			timestamp: signData.timestamp,
			version: signData.version
		}
		// 响应报文内待签名的明文数据
		const responseSignStr = RSA.getKeyVal(data);
		const isValid = RSA.signVerify(responseSignStr, signature)
		return isValid
	}
}