'use strict';

function Version(version) {
  this.version = version;
  return this;
};

Version.prototype.getBaseVersion = function() {
  return this.version % Version.AUXPOW;
};

Version.prototype.getChainId = function() {
  return Math.floor(this.version / Version.CHAIN_START);
};

Version.prototype.isAuxPow = function() {
  return (this.version & Version.AUXPOW) !== 0;
};

Version.prototype.isLegacy = function() {
  return this.version < Version.AUXPOW;
};

Version.AUXPOW = 0x100;
Version.CHAIN_START = 0x10000;
Version.CHAIN_ID = 32;

module.exports = Version;
