'use strict';

var _ = require('lodash');
var inherits = require('inherits');
var BufferUtil = require('../util/buffer');
var BufferWriter = require('../encoding/bufferwriter');

var Transaction = require('../transaction');

/**
 * @desc
 * Wrapper around Transaction
 *
 * @param {Transaction} arg
 * @constructor
 */
function MerkleTransaction(arg) {
  if (!(this instanceof MerkleTransaction)) {
    return new MerkleTransaction(arg);
  }
  if (arg instanceof MerkleTransaction) {
    return arg;
  }
  if (BufferUtil.isBuffer(arg)) {
    return this._fromBufferReader(arg);
  }
  if (_.isObject(arg)) {
    return this._fromObject(arg);
  }
  throw new errors.InvalidArgument('MerkleTransaction must be instantiated from an object');
}
inherits(MerkleTransaction, Transaction);

MerkleTransaction.prototype._fromBufferReader = function(reader) {
  this.redundantParentBlockHash = reader.read(32);
  var size = reader.readVarintNum();
  this.merkleBranch = []; // merkle branch of coinbase link
  for (var i = 0; i < size; i++) {
    this.merkleBranch.push(reader.read(32));
  }
  this.merkleBranchSideMask = reader.readUInt32LE(); // branch sides bitmask
  return this;
};

MerkleTransaction.prototype._fromObject = function(arg) {
  this.redundantParentBlockHash = arg.redundantParentBlockHash;
  this.merkleBranch = arg.merkleBranch;
  this.merkleBranchSideMask = arg.merkleBranchSideMask;
  return this;
};

MerkleTransaction.prototype.toBufferWhole = function() {
  var writer = new BufferWriter();
  return this.toBufferWriterWhole(writer).toBuffer();
};

MerkleTransaction.prototype.toBufferWriterWhole = function(writer) {
  writer.write(this.redundantParentBlockHash);
  writer.writeVarintNum(this.merkleBranch.length);
  this.merkleBranch.forEach(function(m) {
    writer.write(m);
  });
  writer.writeUInt32LE(this.merkleBranchSideMask);
  return writer;
};

module.exports = MerkleTransaction;
