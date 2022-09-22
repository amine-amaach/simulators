const { Root } = require('protobufjs');

protobufjs = require('protobufjs');
fs = require('fs');

module.exports = function (RED) {
    function ProtoFileNode (config) {
        RED.nodes.createNode(this, config);
        if (config.protopath.includes(",")) {
            this.protopath = config.protopath.split(",");
        }
        else {
            this.protopath = config.protopath;
        }
        this.watchFile = config.watchFile;
        this.keepCase = config.keepCase;
        protoFileNode = this;
        protoFileNode.load = function () {
            try {
                protoFileNode.protoTypes = new Root().loadSync(protoFileNode.protopath, { keepCase: protoFileNode.keepCase });
            }
            catch (error) {
                protoFileNode.error('Proto file could not be loaded. ' + error);
            }
        };
        protoFileNode.watchFile = function () {
            try {
                // if it's an array, just watch the first one, it's most likely the one likely to change.
                // As the subsequent files are more likely dependencies on the root.
                let watchedFile = protoFileNode.protopath;
                if (Array.isArray(watchedFile)) {
                    watchedFile = watchedFile[0];
                }
                protoFileNode.protoFileWatcher = fs.watch(watchedFile, (eventType) => {
                    if (eventType === 'change') {
                        protoFileNode.load();
                        protoFileNode.log('Protobuf file changed on disk. Reloaded.');
                    }
                });
                protoFileNode.on('close', () => {
                    protoFileNode.protoFileWatcher.close();
                });
            }
            catch (error) {
                protoFileNode.error('Error when trying to watch the file on disk: ' + error);
            }
        };
        protoFileNode.load();
        if (protoFileNode.protoTypes !== undefined && protoFileNode.watchFile) protoFileNode.watchFile();
    }
    RED.nodes.registerType('protobuf-file', ProtoFileNode);
};
