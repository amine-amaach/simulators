protobufjs = require('protobufjs');

module.exports = function (RED) {
    function ProtobufDecodeNode (config) {
        RED.nodes.createNode(this, config);
        // Retrieve the config node
        this.protofile = RED.nodes.getNode(config.protofile);
        this.protoType = config.protoType;
        var node = this;

        let resolveMessageType = function (msg) {
            msg.protobufType = msg.protobufType || node.protoType;
            if (msg.protobufType === undefined) {
                node.error('No protobuf type supplied!');
                return node.status({fill: 'red', shape: 'dot', text: 'Protobuf type missing'});
            }
            if (node.protofile.protoTypes === undefined) {
                node.error('No .proto types loaded! Check that the file exists and that node-red has permission to access it.');
                return node.status({fill: 'red', shape: 'dot', text: 'Protofile not ready'});
            }
            node.status({fill: 'green', shape: 'dot', text: 'Ready'});
            let messageType;
            try {
                messageType = node.protofile.protoTypes.lookupType(msg.protobufType);
            }
            catch (error) {
                node.warn(`
Problem while looking up the message type.
${error}
Protofile object:
${node.protofile.protopath}
Prototypes content:
${JSON.stringify(node.protofile.protoTypes)}
With configured protoType:
${msg.protobufType}
                `);
                node.status({fill: 'yellow', shape: 'dot', text: 'Message type not found'});
            }
            return messageType;
        };

        node.on('input', function (msg) {
            let messageType = resolveMessageType(msg);
            if (!messageType) return;
            let message;
            try {
                message = messageType.decode(msg.payload);
            }
            catch (exception) {
                if (exception instanceof protobufjs.util.ProtocolError) {
                    node.warn('Received message contains empty fields. Incomplete message will be forwarded.');
                    node.status({fill: 'yellow', shape: 'dot', text: 'Message incomplete'});
                    msg.payload = e.instance;
                    node.send(msg);
                }
                else {
                    node.warn(`Wire format is invalid: ${exception}`);
                    return node.status({fill: 'yellow', shape: 'dot', text: 'Wire format invalid'});
                }
            }
            let decodeOptions = {
                longs: String,
                enums: String,
                bytes: String,
                defaults: false, // includes default values, otherwise not transmitted values will be assigned their default value!
            };
            msg.payload = messageType.toObject(message, decodeOptions);
            node.status({fill: 'green', shape: 'dot', text: 'Processed'});
            node.send(msg);
        });
    }
    RED.nodes.registerType('decode', ProtobufDecodeNode);
};
