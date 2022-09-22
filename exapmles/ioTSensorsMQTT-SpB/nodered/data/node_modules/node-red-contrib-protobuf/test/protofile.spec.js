var should = require('should');
var helper = require('node-red-node-test-helper');
var protofile = require('../src/nodes/protofile');
var fs = require('fs');
const { SSL_OP_EPHEMERAL_RSA } = require('constants');
const { time } = require('console');

helper.init(require.resolve('node-red'));

describe('protobuf protofile node', function () {

  afterEach(function () {
    helper.unload();
    should();
  });

  it('test.proto should be loadable', function (done) {
    fs.access('test/assets/test.proto', (error) => {
        if (!error) done();
    });
  });

  it('should be loaded', function (done) {
    var flow = [{ id: 'n1', type: 'protobuf-file', name: 'test name', protopath: 'test/assets/test.proto' }];
    helper.load(protofile, flow, function () {
      var n1 = helper.getNode('n1');
      n1.should.have.property('name', 'test name');
      n1.should.have.property('protopath', 'test/assets/test.proto');
      n1.should.have.property('protoTypes').which.is.a.Object();
      done();
    });
  });

  it('should reload on file change', function (done) {
    fs.copyFileSync('test/assets/test.proto', '/tmp/test.proto');
    var flow = [{ id: 'n1', type: 'protobuf-file', name: 'test name', protopath: '/tmp/test.proto' }];
    helper.load(protofile, flow, function () {
      fs.copyFileSync('test/assets/complex.proto', '/tmp/test.proto');
      let n1 = helper.getNode('n1');
      setTimeout(() => {
        n1.protoTypes.should.have.property('Zaehler_Waerme').which.is.a.Object();
        done();
      }, 25);
    });
  });

  it('should load multiple files', function (done) {
    var flow = [{ id: 'n1', type: 'protobuf-file', name: 'test name', protopath: 'test/assets/test.proto,test/assets/issue3.proto' }];
    helper.load(protofile, flow, function () {
      var n1 = helper.getNode('n1');
      if (!Array.isArray(n1['protopath'])) return done(Error("protopath does not contain multiple files"))
      if (n1['protoTypes']['TestType'] === undefined || n1['protoTypes']['Viessmann'] === undefined) return done(Error('not all types loaded'))
      done()
    });
  });

});
