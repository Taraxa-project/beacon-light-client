.PHONY: all fmt clean test
.PHONY: tools foundry sync

-include .env

all    :; @forge build --force
fmt    :; @forge fmt
clean  :; @forge clean
test   :; @forge test

deploy :; @forge script script/Deploy.s.sol:Deploy --rpc-url http://127.0.0.1:7777 --broadcast --legacy --private-key 0xfc6c309495809b69ce77b3250cacfef94d28698d8fb425501a59836fe30fab1d -vvvv --optimize --optimizer-runs 200 --slow
e2e-test:; @forge script script/LightClientTest.s.sol:LightClientTest --fork-url http://127.0.0.1:7777 --broadcast --legacy --private-key 0xfc6c309495809b69ce77b3250cacfef94d28698d8fb425501a59836fe30fab1d -vvvv --skip-simulation

sync   :; @git submodule update --recursive

tools  :  foundry
foundry:; curl -L https://foundry.paradigm.xyz | bash
