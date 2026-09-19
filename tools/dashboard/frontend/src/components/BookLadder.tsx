import type { BookSide } from "../types";

const fmtTicks = (ticks: number) => (ticks / 10000).toFixed(4);

export function BookLadder({ book, symbol }: { book?: BookSide; symbol: string }) {
  if (!book) {
    return <div className="scroll">no book yet for {symbol}</div>;
  }
  const bids = book.bids ?? [];
  const asks = book.asks ?? [];
  const maxQty = Math.max(
    1,
    ...bids.map(([, q]) => q),
    ...asks.map(([, q]) => q),
  );
  const spread = asks.length && bids.length ? asks[0][0] - bids[0][0] : 0;

  const row = (side: "bid" | "ask", price: number, qty: number) => (
    <div className={`book-row ${side}`} key={`${side}-${price}`}>
      <span className="px">{fmtTicks(price)}</span>
      <span className="qty">{qty.toLocaleString()}</span>
      <span className="bar" style={{ width: `${(qty / maxQty) * 100}%` }} />
      <span />
    </div>
  );

  return (
    <>
      <div style={{ fontSize: 12, color: "#8b949e", marginBottom: 4 }}>
        {symbol} — spread {fmtTicks(spread)} ({spread.toLocaleString()} ticks)
      </div>
      <div className="book-grid">
        <div className="book-side">
          <h3>bids ({bids.length})</h3>
          {bids.map(([p, q]) => row("bid", p, q))}
        </div>
        <div className="book-side">
          <h3>asks ({asks.length})</h3>
          {asks.map(([p, q]) => row("ask", p, q))}
        </div>
      </div>
    </>
  );
}
