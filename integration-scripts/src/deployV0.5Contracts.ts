import { LinkTokenV05Factory } from './generated/LinkTokenV05Factory'
import { CoordinatorFactory } from './generated/CoordinatorFactory'
import { MeanAggregatorFactory } from './generated/MeanAggregatorFactory'
import { GetterSetterFactory } from './generated/GetterSetterFactory'
import { ethers } from 'ethers'

export async function deployContracts(provider: ethers.providers.JsonRpcProvider, DEVNET_ADDRESS: string) {
  const signer = provider.getSigner(DEVNET_ADDRESS)


  // deploy LINK token
  const linkTokenFactory = new LinkTokenV05Factory(signer)
  const linkToken = await linkTokenFactory.deploy()
  await linkToken.deployed()
  console.log(`Deployed LinkToken at: ${linkToken.address}`)

  // deploy Coordinator
  const coordinatorFactory = new CoordinatorFactory(signer)
  const coordinator = await coordinatorFactory.deploy(linkToken.address)
  await coordinator.deployed()
  console.log(`Deployed Coordinator at: ${coordinator.address}`)

  // deploy MeanAggregator
  const meanAggregatorFactory = new MeanAggregatorFactory(signer)
  const meanAggregator = await meanAggregatorFactory.deploy()
  await meanAggregator.deployed()
  console.log(`Deployed MeanAggregator at: ${meanAggregator.address}`)

  const getterSetterFactory = new GetterSetterFactory(signer)
  const getterSetter = await getterSetterFactory.deploy()
  await getterSetter.deployed()
  console.log(`Deployed GetterSetter at: ${getterSetter.address}`)

  return {
    linkToken,
    coordinator,
    meanAggregator,
    getterSetter
  }
}
