const debug = require('debug')('hrbac');

function any(promises) {
    if(promises.length < 1) {
        return Promise.resolve(false);
    }
    return Promise.all(
        promises.map($p =>
            $p
                .catch(err => {
                    debug('Underlying promise rejected', err);
                    return false;
                })
                .then(result => {
                    if(result) {
                        throw result;
                    }
                })
        )
    )
        .then(() => false)
        .catch(result => result);
}

function isGlob(string) {
    return string.includes('*');
}

function globToRegex(string) {
    return new RegExp(string.replace(/\*/g, '.*'));
}

module.exports = {
    any,
    isGlob,
    globToRegex
};