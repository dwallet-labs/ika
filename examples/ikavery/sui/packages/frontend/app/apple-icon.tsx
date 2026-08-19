import { ImageResponse } from 'next/og';

export const size = { width: 180, height: 180 };
export const contentType = 'image/png';

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

export default function AppleIcon() {
	const ink = '#0B0B0B';
	const bone = '#F4EDE3';
	const clay = '#C8854A';
	const cell = 9;
	const W = grid[0]!.length * cell;
	const H = grid.length * cell;

	return new ImageResponse(
		<div
			style={{
				width: '100%',
				height: '100%',
				background: bone,
				display: 'flex',
				alignItems: 'center',
				justifyContent: 'center',
			}}
		>
			<svg
				width={W}
				height={H}
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
		</div>,
		{ ...size },
	);
}
