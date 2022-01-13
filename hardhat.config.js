require("@tenderly/hardhat-tenderly");

module.exports = {
  networks: {
    hardhat: {
      forking: {
      url: "http://127.0.0.1:8545",
      },
      hardfork: "london",
    }
  },
  tenderly: {
    project: "project",
    username: "grw",
}
}
