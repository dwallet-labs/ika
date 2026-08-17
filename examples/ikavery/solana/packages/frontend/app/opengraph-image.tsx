import { ImageResponse } from 'next/og';

export const alt = 'Ikavery · Solana keys kept by quorum';
export const size = { width: 1200, height: 630 };
export const contentType = 'image/png';

export default async function OpengraphImage() {
	const ink = '#0B0B0B';
	const bone = '#F4EDE3';
	const clay = '#C8854A';
	const iron = '#3A3A3A';

	// 16x10 grid; "1" = ink, "2" = clay, "0" = empty.
	const grid = [
		'0000011110000000',
		'0000111111000000',
		'0001111111110000',
		'0001101101100000',
		'0001111111100222',
		'0001111111111202',
		'0001111111120222',
		'0000111111000000',
		'0001010101000000',
		'0010101010100000',
	];
	const cell = 16;

	return new ImageResponse(
		<div
			style={{
				width: '100%',
				height: '100%',
				display: 'flex',
				flexDirection: 'column',
				background: bone,
				padding: '72px 88px',
				fontFamily: 'serif',
				position: 'relative',
			}}
		>
			<div
				style={{
					position: 'absolute',
					top: 72,
					right: 88,
					display: 'flex',
					flexDirection: 'column',
					alignItems: 'flex-end',
				}}
			>
				<svg
					width={grid[0]!.length * cell}
					height={grid.length * cell}
					viewBox={`0 0 ${grid[0]!.length} ${grid.length}`}
					shapeRendering="crispEdges"
				>
					{grid.flatMap((row, y) =>
						row
							.split('')
							.map((c, x) =>
								c === '0' ? null : (
									<rect
										key={`${x},${y}`}
										x={x}
										y={y}
										width={1}
										height={1}
										fill={c === '2' ? clay : ink}
									/>
								),
							),
					)}
				</svg>
			</div>

			<div
				style={{
					fontSize: 22,
					letterSpacing: 6,
					textTransform: 'uppercase',
					color: clay,
					fontFamily: 'sans-serif',
				}}
			>
				Proof of concept · Solana · Ika · Dynamic
			</div>

			<div
				style={{
					marginTop: 'auto',
					display: 'flex',
					flexDirection: 'column',
				}}
			>
				<div
					style={{
						fontSize: 168,
						lineHeight: 0.94,
						letterSpacing: -6,
						color: ink,
						fontFamily: 'serif',
					}}
				>
					Ikavery.
				</div>
				<div
					style={{
						marginTop: 12,
						fontSize: 64,
						lineHeight: 1,
						letterSpacing: -2,
						color: iron,
						fontStyle: 'italic',
						fontFamily: 'serif',
					}}
				>
					Keys kept by quorum.
				</div>
				<div
					style={{
						marginTop: 36,
						fontSize: 24,
						lineHeight: 1.45,
						color: iron,
						fontFamily: 'sans-serif',
						maxWidth: 760,
					}}
				>
					Place a Solana key behind a threshold of wallets you already trust. Recover it any time by
					signing on a quorum.
				</div>
			</div>
		</div>,
		{ ...size },
	);
}
