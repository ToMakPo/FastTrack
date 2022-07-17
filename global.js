const moment = require('moment');

const UNCOMMON_LETTERS = 'ÁáÀàÂâÄäÃãÅåÆæÇçÐðÉéÈèÊêËëÍíÌìÎîÏïÑñÓóÒòÔôÖöÕõŠšÚúÙùÛûÜüÝýŸÿŽž'
const CHARACTERS_IN_NAMES = 'a-z\\s_\\\'\\.\\-\\\\' + UNCOMMON_LETTERS

module.exports = {
    getWeekOf: date => date.format('GGGG.WW'),
    makeID: _ => Math.floor(Math.random() * 36**9).toString(36).padStart(9, '0').toUpperCase(),
    LogError: message => console.error('\x1b[31m' + message + '\x1b[0m'),
    UNCOMMON_LETTERS,
    CHARACTERS_IN_NAMES
}