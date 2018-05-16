const validate = require('validate.js');
const jwt = require('jsonwebtoken');

const HRBAC = require('./hrbac');
const Encryption = require('./encryption');

class ExpressSecurity {
    static create(opts) {
        return new ExpressSecurity(opts);
    }

    constructor({roles = {}, encryptionPass = '', secretJWT = ''}) {
        this.hrbac = new HRBAC(roles);
        this.encryption = new Encryption(encryptionPass);
        this.secretJWT = secretJWT;
    }

    generateToken(_id, roles, data = {}, expire = '30d') {
        return this.encryption.encrypt(jwt.sign({...data, _id, roles}, this.secretJWT, {expiresIn: expire}))
    }

    validateToken(bearer) {
        if (!bearer) throw 'No bearer provided';
        let decryptedBearer = this.encryption.decrypt(bearer.replace('Bearer ', ''));
        let payload = jwt.verify(decryptedBearer, this.secretJWT);
        if (validate(payload, {
            roles: {presence: true},
            _id: {presence: true},
        })) throw 'Unauthorized';
        if (payload.iat >= payload.exp) throw 'Unauthorized';
        return payload;
    }

    securise(operation, params = ()=>{}) {
        return async (req, res, next) => {
            try {
                let currentUser = req.user || this.validateToken(req.headers.authorization);
                req.user = currentUser;
                let isAuthorized = await this.hrbac.can(currentUser.roles, operation, params(currentUser, req));
                if (!isAuthorized) throw 'Unauthorize';
                next();
            }
            catch (e) {
                res.status(401).send('Unauthorize');
            }
        }
    }
}

module.exports = ExpressSecurity;