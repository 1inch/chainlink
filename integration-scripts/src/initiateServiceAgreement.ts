import { helpers } from 'chainlink'
import { getArgs, registerPromiseHandler } from './common'
import { CoordinatorFactory } from './generated/CoordinatorFactory'
import agreementJson from './fixtures/agreement.json'
import { ethers } from 'ethers'
// import { LinkTokenFactory } from './generated/LinkTokenFactory'
import { Coordinator } from './generated/Coordinator'
import { MeanAggregatorFactory } from './generated/MeanAggregatorFactory'
// import { GetterSetterFactory } from './generated/GetterSetterFactory'
import { createTraceProvider } from './common'
import { deployContracts } from './deployV0.5Contracts'

async function main() {
  registerPromiseHandler()
  const { defaultFromAddress, provider } = await createTraceProvider()
  const { linkToken, coordinator, meanAggregator, getterSetter } = await deployContracts(
    provider,
    defaultFromAddress,
  )

  process.env.LINK_TOKEN_ADDRESS = linkToken.address
  process.env.COORDINATOR_ADDRESS = coordinator.address
  process.env.MEAN_AGGREGATOR_ADDRESS = meanAggregator.address
  process.env.GETTER_SETTER_ADDRESS = getterSetter.address
  process.env.ORACLE_SIGNATURE =
    '0xc846280320ffef933ce090706c61945865e3407cbf35b6a3edd63cf11e2190206f531499c7d3b748a3538ed41bf0df76ad421704d7ab89131ae3b11654ce62b701'
  process.env.NORMALIZED_REQUEST =
    '{"aggFulfillSelector":"0xbadc0de5","aggInitiateJobSelector":"0xd0771e55","aggregator":"0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF","endAt":"2019-10-19T22:17:19Z","expiration":3.000000e+02,"initiators":[{"type":"execagreement"}],"oracles":["0x9CA9d2D5E04012C9Ed24C0e513C9bfAa4A2dD77f"],"payment":"1000000000000000000","tasks":[{"params":{"get":"https://bitstamp.net/api/ticker/"},"type":"HttpGet"},{"params":{"path":["last"]},"type":"JsonParse"},{"type":"EthBytes32"},{"params":{"address":"0x356a04bce728ba4c62a30294a55e6a8600a320b3","functionSelector":"0x609ff1bd"},"type":"EthTx"}]}'

  const args = getArgs([
    'LINK_TOKEN_ADDRESS',
    'COORDINATOR_ADDRESS',
    'MEAN_AGGREGATOR_ADDRESS',
    'GETTER_SETTER_ADDRESS',
    'ORACLE_SIGNATURE',
    'NORMALIZED_REQUEST',
  ])

  await initiateServiceAgreement({
    linkTokenAddress: args.LINK_TOKEN_ADDRESS,
    coordinatorAddress: args.COORDINATOR_ADDRESS,
    meanAggregatorAddress: args.MEAN_AGGREGATOR_ADDRESS,
    getterSetterAddress: args.GETTER_SETTER_ADDRESS,
    normalizedRequest: args.NORMALIZED_REQUEST,
    oracleSignature: args.ORACLE_SIGNATURE,
    provider,
    DEVNET_ADDRESS: defaultFromAddress,
  })
}
main()

interface Args {
  linkTokenAddress: string
  coordinatorAddress: string
  meanAggregatorAddress: string
  getterSetterAddress: string
  oracleSignature: string
  normalizedRequest: string
  provider: ethers.providers.JsonRpcProvider
  DEVNET_ADDRESS: string
}

async function initiateServiceAgreement({
  // linkTokenAddress,
  coordinatorAddress,
  meanAggregatorAddress,
  // getterSetterAddress,
  normalizedRequest,
  oracleSignature,
  provider,
  DEVNET_ADDRESS,
}: Args) {
  const signer = provider.getSigner(DEVNET_ADDRESS)
  // const linkTokenFactory = new LinkTokenFactory(signer)
  // const linkToken = linkTokenFactory.attach(linkTokenAddress)
  const coordinatorFactory = new CoordinatorFactory(signer)
  const coordinator = coordinatorFactory.attach(coordinatorAddress)
  const meanAggregator = new MeanAggregatorFactory()
  // const getterSetterFactory = new GetterSetterFactory()

  type CoordinatorParams = Parameters<Coordinator['initiateServiceAgreement']>
  type ServiceAgreement = CoordinatorParams[0]
  type OracleSignatures = CoordinatorParams[1]

  const agreement: ServiceAgreement = {
    aggFulfillSelector: meanAggregator.interface.functions.fulfill.sighash,
    aggInitiateJobSelector:
      meanAggregator.interface.functions.initiateJob.sighash,
    aggregator: meanAggregatorAddress,
    payment: agreementJson.payment,
    expiration: agreementJson.expiration,
    endAt: Math.round(new Date(agreementJson.endAt).getTime() / 1000), // end date in seconds
    oracles: agreementJson.oracles,
    requestDigest: ethers.utils.keccak256(
      ethers.utils.toUtf8Bytes(normalizedRequest),
    ),
  }

  const sig = ethers.utils.splitSignature(oracleSignature)
  if (!sig.v) {
    throw Error(`Could not extract v from signature`)
  }
  const oracleSignatures: OracleSignatures = {
    rs: [sig.r],
    ss: [sig.s],
    vs: [sig.v],
  }

  const said = helpers.calculateSAID2(agreement)

  const ssaid = await coordinator.getId(agreement)
  if (said != ssaid) {
    throw Error(`sAId mismatch. javascript: ${said} solidity: ${ssaid}`)
  }

  // const meanAggregator = new MeanAggregatorFactory(signer).attach(
  //   meanAggregatorAddress,
  // ).functions.initiateJob

  // meanAggregator.initiateJob(said, agreement)

  console.log('meanAggregator call worked...')

  const tx = await coordinator.initiateServiceAgreement(
    agreement,
    oracleSignatures,
  )
  console.log(tx)

  const iSAreceipt = await tx.wait()
  console.log('initiateServiceAgreement receipt', iSAreceipt)

  // // 1. Identify the signer used to initiate the link token. They have the full
  // //    balance. defaultFromAddress
  // //
  // // 2. If that's different from the account we're using to make the transaction
  // //    here, pay the necessary account. Might as well just do this from the
  // //    initial account, though?
  // //
  // // 3. Construct the message for link's transferAndCall using
  // //    oldHelpers.executeServiceAgreementBytes.
  // //
  // // 4. Run the transaction.

  // // LINK's transferAndCall will pass this to the coordinator. It specifies
  // // routing of the eventual response.
  // const requestCallbackData = oldHelpers.executeServiceAgreementBytes(
  //   said,
  //   getterSetterAddress,
  //   getterSetterFactory.interface.functions.requestedBytes32.sighash,
  //   1,  // Data version
  //   ''  // Extra data to be passed to the oracle with the  request
  // )

//   const paymentTx = await linkToken.transferAndCall(
//     coordinatorAddress,
//     agreement.payment,
//     requestCallbackData,
//   )

//   // const reqId = await coordinator.oracleRequest(
//   //   '0x0101010101010101010101010101010101010101',
//   //   10000000000000,
//   //   said as any, // XXX:
//   //   '0x0101010101010101010101010101010101010101', // Receiving contract address
//   //   '0x12345678', // receiving method selector
//   //   1, // nonce
//   //   1, // data version
//   //   '0x0', // data for initialization of request
//   // )
//   const receipt = await paymentTx.wait()
//   console.log(
//     '************************************************************************ oracleRequest',
//     receipt,
//   )
// }

// function coordinatorRequest(
//   coordinator: Coordinator,
//   sAID: string,
//   callbackAddr: string,
//   callbackFunctionId: string,
//   nonce: number,
//   data: string,
// ): string {
//   const types = [
//     'address', // sender
//     'uint256', // payment amount
//     'bytes32', // sAId
//     'address', // contract callback address
//     'bytes4',  // contract callback method
//     'uint256', // nonce
//     'uint256', // data version
//     'bytes',   // extra data for oracle
//   ]
//   const values = [0, 0, sAID, callbackAddr, callbackFunctionId, nonce, 1, data]
//   const encoded = abiEncode(types, values)
//   const funcSelector = functionSelector(
//     'oracleRequest(address,uint256,bytes32,address,bytes4,uint256,uint256,bytes)',
//   )
//   return funcSelector + encoded
}
