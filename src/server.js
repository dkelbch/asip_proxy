/*!
    \brief start SIP proxy
*/

const cp_sipProxy = require('./core_sipproxy');
var     account = require('./../data/accounts.json');

async   function    configLoad(_baseDir){
    let config = {
        srv:{port:5060, transport:"udp"},
        accounts: account.accounts
    }

    let obj = await cp_sipProxy.start(config);
}

configLoad('.');


