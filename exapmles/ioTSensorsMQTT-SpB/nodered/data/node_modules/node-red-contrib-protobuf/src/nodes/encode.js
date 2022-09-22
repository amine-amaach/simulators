module.exports = function (RED) {
    function ProtobufEncodeNode (config) {
        RED.nodes.createNode(this, config);
        // Retrieve the config node
        this.protofile = RED.nodes.getNode(config.protofile);
        this.protoType = config.protoType;
        var node = this;
        node.on('input', function (msg) {
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
                return node.status({fill: 'yellow', shape: 'dot', text: 'Message type not found'});
            }
            if (messageType.verify(msg.payload)) {
                node.warn('Message is not valid under selected message type.');
                return node.status({fill: 'yellow', shape: 'dot', text: 'Message invalid'});
            }
            // create a protobuf message and convert it into a buffer
            msg.payload = messageType.encode(messageType.create(msg.payload)).finish();
            node.status({fill: 'green', shape: 'dot', text: 'Processed'});
            node.send(msg);
        });
    }
    RED.nodes.registerType('encode', ProtobufEncodeNode);
};
