const validate = require('validate.js');
const jwt = require('jsonwebtoken');

const HRBAC = require('./hrbac');
const Encryption = require('./encryption');

class ExpressSecurity {
    static create(opts) {
        return new ExpressSecurity(opts);
    }

    constructor({roles = {}, encryptionPass = '', secretJWT = '', transformError}) {
        this.hrbac = new HRBAC(roles);
        this.encryption = new Encryption(encryptionPass);
        this.secretJWT = secretJWT;
        this.transformError = transformError;
    }

    generateToken(_id, roles, data = {}, expire = '30d') {
        return this.encryption.encrypt(jwt.sign({...data, _id, roles}, this.secretJWT, {expiresIn: expire}))
    }

    validateToken(bearer) {
        try {
            if (!bearer) throw 'No bearer provided';
            let decryptedBearer = this.encryption.decrypt(bearer.replace('Bearer ', ''));
            let payload = jwt.verify(decryptedBearer, this.secretJWT);
            if (validate(payload, {
                roles: {presence: true},
                _id: {presence: true},
            })) throw 'Unauthorized';
            if (payload.iat >= payload.exp) throw 'Unauthorized';
            return {
                ...payload,
                authenticated : true
            };
        }
        catch (e) {
            return {
                authenticated : false,
                roles : ['guest']
            };
        }
    }

    access(operation, params = ()=>{}) {
        return async (req, res, next) => {
            try {
                let currentUser = req.user || this.validateToken(req.headers.authorization);
                req.user = currentUser;
                let isAuthorized = await this.hrbac.can(currentUser.roles, operation, await params(currentUser, req));
                if (!isAuthorized) throw 'not authorized';
                next();
            }
            catch (e) {
                this.transformError ? await this.transformError(req, res, next) : res.status(403).send('Forbidden');
            }
        }
    }
}

module.exports = ExpressSecurity;