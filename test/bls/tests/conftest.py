import json
import os
import pytest

from eth.vm.forks.berlin import BerlinVM
from py_ecc.bls.ciphersuites import G2ProofOfPossession
from py_ecc.bls.g2_primatives import pubkey_to_G1, signature_to_G2
from py_ecc.optimized_bls12_381.optimized_curve import normalize
from web3 import HTTPProvider, Web3
from solcx import link_code

DIR = os.path.dirname(__file__)


def _get_json(filename):
    with open(filename) as f:
        return json.load(f)


def get_bls_contract_json():
    filename = os.path.join(DIR, "../../../out/BLS.t.sol/BLSTest.json")
    return _get_json(filename)

def get_bls_library_json():
    filename = os.path.join(DIR, "../../../out/BLS.sol/BLS.json")
    return _get_json(filename)

@pytest.fixture
def w3():
    web3 = Web3(HTTPProvider("http://127.0.0.1:7777"))
    return web3

@pytest.fixture
def private_key():
    return "0xfc6c309495809b69ce77b3250cacfef94d28698d8fb425501a59836fe30fab1d"

@pytest.fixture
def account(w3, private_key):
    return w3.eth.account.from_key(private_key)

def _deploy_contract(contract_json, w3, account, *args):
    contract_bytecode = contract_json["bytecode"]["object"]
    bls_lib = bls_library(w3, account)
    contract_bytecode = link_code(contract_bytecode, {'src/bls12381/BLS.sol:BLS': bls_lib})
    contract_abi = contract_json["abi"]
    registration = w3.eth.contract(abi=contract_abi, bytecode=contract_bytecode)
    nonce = w3.eth.get_transaction_count(account.address)
    transaction = registration.constructor(*args).build_transaction({
        'from': account.address,
        'nonce': nonce,
        'gas': 2000000,  # Set appropriate gas limit
        'gasPrice': w3.to_wei('1', 'wei')  # Set appropriate gas price
    })
    signed_txn = account.sign_transaction(transaction)
    tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)

    # Custom timeout and poll_latency values
    custom_timeout = 180  # e.g., 180 seconds
    custom_poll_latency = 0.5  # e.g., 0.2 seconds
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=custom_timeout, poll_latency=custom_poll_latency)

    contract_deployed = w3.eth.contract(
        address=tx_receipt.contractAddress, abi=contract_abi
    )
    return contract_deployed

def _deploy_library(contract_json, w3, account, *args):
    contract_bytecode = contract_json["bytecode"]["object"]
    contract_abi = contract_json["abi"]
    registration = w3.eth.contract(abi=contract_abi, bytecode=contract_bytecode)

    nonce = w3.eth.get_transaction_count(account.address)
    transaction = registration.constructor(*args).build_transaction({
        'from': account.address,
        'nonce': nonce,
        'gas': 2000000,  # You might need to adjust this value
        'gasPrice': w3.to_wei('1', 'wei')  # You might need to adjust this value
    })

    signed_txn = account.sign_transaction(transaction)
    tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)

    custom_timeout = 180  # e.g., 180 seconds
    custom_poll_latency = 0.5  # e.g., 0.2 seconds
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=custom_timeout, poll_latency=custom_poll_latency)

    return tx_receipt.contractAddress


@pytest.fixture
def bls_contract(w3, account):
    return _deploy_contract(get_bls_contract_json(), w3, account)

def bls_library(w3, account):
    return _deploy_library(get_bls_library_json(), w3, account)


@pytest.fixture
def assert_call_fail():
    def assert_call_fail(func, msg, exception=eth_tester.exceptions.TransactionFailed):
        with pytest.raises(exception, match=msg):
            func()
    return assert_call_fail


@pytest.fixture
def seed():
    return "some-secret".encode()


@pytest.fixture
def bls_private_key(seed):
    return G2ProofOfPossession.KeyGen(seed)


@pytest.fixture
def bls_public_key(bls_private_key):
    return G2ProofOfPossession.SkToPk(bls_private_key)


@pytest.fixture
def signing_root():
    return bytes.fromhex('3a896ca4b5db102b9dfd47528b06220a91bd12461dcc86793ce2d591f41ea4f8')


@pytest.fixture
def signature(bls_private_key, signing_root):
    return G2ProofOfPossession.Sign(bls_private_key, signing_root)


@pytest.fixture
def public_key_witness(bls_public_key):
    group_element = pubkey_to_G1(bls_public_key)
    normalized_group_element = normalize(group_element)
    return normalized_group_element[1]


@pytest.fixture
def signature_witness(signature):
    group_element = signature_to_G2(signature)
    normalized_group_element = normalize(group_element)
    return normalized_group_element[1]


@pytest.fixture
def dst():
    return G2ProofOfPossession.DST
