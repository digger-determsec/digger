// SAFE: View function checks reentrancy lock before reading state.
// Per OpenZeppelin #4422, the consumer of a reentrancy-guarded state must also
// check the lock. This pattern uses _reentrancyGuardEntered() to detect if
// the view is being called during a reentrancy window.
contract SafeViewReentrancyCheck {
    uint256 private _NOT_ENTERED = 1;
    uint256 private _ENTERED = 2;
    uint256 private _status;

    address public pool;
    mapping(address => uint256) public reserves;
    uint256 public price;

    modifier nonReentrant() {
        require(_status != _ENTERED, "reentrant");
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }

    // SAFE: view checks the reentrancy lock before reading price
    function getPrice() public view returns (uint256) {
        // If we're inside a reentrancy window, return stale price (or revert)
        if (_status == _ENTERED) {
            revert("reentrancy detected in view");
        }
        return price;
    }

    function swap(address token, uint256 amount) external nonReentrant {
        IERC20(token).transferFrom(msg.sender, address(this), amount);

        // State read AFTER external call - but getPrice() checks reentrancy lock
        uint256 currentPrice = getPrice();
        uint256 output = (amount * currentPrice) / 1e18;

        reserves[token] += amount;
    }

    function setPrice(uint256 newPrice) external {
        price = newPrice;
    }
}

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
}
