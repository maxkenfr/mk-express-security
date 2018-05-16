const crypto = require('crypto');
const algorithm = 'aes-256-ctr';

class Encryption {
    constructor(encryptionPass){
        this.password_hash = crypto.createHash('md5').update(encryptionPass, 'utf-8').digest('hex').toUpperCase();
        this.iv = new Buffer.alloc(16);
    }
    encrypt(text){
        let cipher = crypto.createCipheriv(algorithm,this.password_hash, this.iv);
        let crypted = cipher.update(text,'utf8','hex');
        crypted += cipher.final('hex');
        return crypted;
    }
    decrypt(text){
        let decipher = crypto.createDecipheriv(algorithm,this.password_hash, this.iv);
        let dec = decipher.update(text,'hex','utf8');
        dec += decipher.final('utf8');
        return dec;
    }
}

module.exports = Encryption;
