// Minimal reproducer of Sentiment read-only reentrancy (May 2023).
// Source: https://rekt.news/sentiment-rekt/ - "Sentiment loses $1M to read-only reentrancy"
//
// Key pattern: price oracle reads state during external call callback.
// Attacker reenters the price oracle during a token transfer callback,
// reading stale price before the pool state is updated.
contract SentimentPool {
    mapping(address => uint256) public reserves;
    uint256 public price;

    // BUG: reads price AFTER external call - price may be stale during callback
    function swap(address token, uint256 amount) external {
        // External call - attacker can reenter during transfer callback
        IERC20(token).transferFrom(msg.sender, address(this), amount);

        // State read AFTER external call - reads stale price if reentered
        uint256 currentPrice = price;
        uint256 output = (amount * currentPrice) / 1e18;

        // State write happens AFTER the read
        reserves[token] += amount;
    }

    function setPrice(uint256 newPrice) external {
        price = newPrice;
    }
}

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
}
