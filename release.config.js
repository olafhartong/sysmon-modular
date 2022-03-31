const baseConfig = require('@quantum-sec/semantic-release-config/base');

for (let i = 0; i < baseConfig.plugins.length; i++) {
  if (baseConfig.plugins[i][0] === '@semantic-release/github') {
    baseConfig.plugins[i][1] = {
      successComment: false,
      failComment: false,
      assets: [{
        path: 'quantum-sysmonconfig.xml',
        label: 'Quantum Security Sysmon Rules'
      }]
    };
  }
}

module.exports = baseConfig;
