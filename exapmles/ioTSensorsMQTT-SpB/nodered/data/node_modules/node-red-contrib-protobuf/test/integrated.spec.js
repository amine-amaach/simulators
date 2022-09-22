var should = require('should');
var helper = require('node-red-node-test-helper');
var encode = require('../src/nodes/encode');
var decode = require('../src/nodes/decode');
var protofile = require('../src/nodes/protofile');

helper.init(require.resolve('node-red'));

const generateIntegratedFlow = function(protoFilePath, protoType, keepCase) { 
    return [
        {
            'id': 'encode-node',
            'type': 'encode',
            'z': 'e4c459b3.cc22e8',
            'name': '',
            'protofile': 'c55e9eb5.3175',
            'protoType': protoType,
            'wires': [
                [
                    'decode-node'
                ]
            ]
        },
        {
            'id': 'decode-node',
            'type': 'decode',
            'z': 'e4c459b3.cc22e8',
            'name': '',
            'protofile': 'c55e9eb5.3175',
            'protoType': protoType,
            'wires': [
                [
                    'helper-node'
                ]
            ]
        },
        {
            'id': 'helper-node',
            'type': 'helper',
            'z': 'e4c459b3.cc22e8',
            'name': '',
            'outputs': 1,
            'noerr': 0,
            'wires': [
                []
            ]
        },
        {
            'id': 'c55e9eb5.3175',
            'type': 'protobuf-file',
            'z': '',
            'protopath': protoFilePath,
            'keepCase': keepCase || false
        }
    ];
}

describe('protobuf integration test', function () {

    afterEach(function () {
        helper.unload();
        should();
    });

    it('should encode and decode a message with idempotence', function (done) {
        helper.load([encode, decode, protofile], generateIntegratedFlow('test/assets/test.proto', 'TestType'), function () {
            let testMessage = {
                timestamp: 1533295590569,
                foo: 1.0,
                bar: true,
                test: 'A string value',
                noMoreSnakeCase: true 
            };
            var encodeNode = helper.getNode('encode-node');
            var helperNode = helper.getNode('helper-node');
            helperNode.on('input', function (msg) {
                JSON.stringify(testMessage).should.equal(JSON.stringify(msg.payload));
                done();
            });
            encodeNode.receive({
                payload: testMessage
            });
        });
    });

    it('should encode and decode a message with underscores in field names', function (done) {
        helper.load([encode, decode, protofile], generateIntegratedFlow('test/assets/issue29.proto', 'Department', true), function () {
            let testMessage = {
                department_id: 12345,
                name: 'Test department'
            };
            var encodeNode = helper.getNode('encode-node');
            var helperNode = helper.getNode('helper-node');
            helperNode.on('input', function (msg) {
                if (JSON.stringify(testMessage) !== JSON.stringify(msg.payload)) return done(Error(`encoded <-> decoded payloads not equal: ${JSON.stringify(testMessage)} !== ${JSON.stringify(msg.payload)}`))
                done();
            });
            encodeNode.receive({
                payload: testMessage
            });
        });
    });

});
