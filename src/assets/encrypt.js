import AES from './AES.js'
import RSA from './RSA.js'
import MD5 from 'crypto-js/md5';
import {Base64} from 'js-base64'

export default class Encrypt {
	constructor(params, deviceInfo) {
		this.options.encryptedData.body = params;
		this.setSystemInfo(deviceInfo);
	}
	options = {
		// 流水号
		sequenceNo: this.getGuid(),
		// 项目版本号
		version: '1.1',
		// 时间戳
		timestamp: new Date().getTime(),
		// 签名
		signature: '',
		// AES随机key及iv组成的json字符串 使用 RSA 加密后的密文
		encryptedKey: '',
		// encryptedData 为以下JSON格式的加密数据
		encryptedData: {
			head: {
				// 设备唯一标识符
				deviceID: '',
				// 设备名称:my iphone
				deviceName: '',
				// 系统类型:Android、iOS
				osType: '',
				// 系统版本:13.3等
				osVersion: '',
				// 设备型号:华为mate30
				phoneType: ''
			},
			// 业务请求参数
			body: ''
		}
	}
	/**
	 * 签名
	 * @return {String} 签名字符串
	 * **/
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

	// 获取encryptedData 和 encryptedKey
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
		// 1. 随机生成AES密钥key(base64编码)，向量iv(16位)
		const key = AES.createAesKey()
		const aesKey = Base64.encode(key)
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
	/**
	 * 生成加密后的数据
	 * **/
	generateData() {
		const encrypted = this.getEncryptedData()
		return {
			sequenceNo: this.options.sequenceNo,
			timestamp: this.options.timestamp,
			version: this.options.version,
			signature: this.sign(),
			encryptedKey: encrypted.encryptedKey,
			encryptedData: encrypted.encryptedData
		}

	}
	/**
	 * 设置系统信息
	 * **/
	setSystemInfo(info) {
		let head = this.options.encryptedData.head;
		return Object.assign(head, info)
	}
	/**
	 * 生成流水号
	 * **/
	getGuid() {
		function S4() {
			return (((1 + Math.random()) * 0x10000) | 0).toString(16).substring(1);
		}
		return (S4() + S4() + "-" + S4() + "-" + S4() + "-" + S4() + "-" + S4() + S4() + S4());
	}
}
