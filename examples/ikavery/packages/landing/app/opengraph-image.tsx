import { ImageResponse } from 'next/og';

export const alt = 'ikavery · threshold-signed key custody';
export const size = { width: 1200, height: 630 };
export const contentType = 'image/png';

const FONT_DISPLAY = 'https://fonts.googleapis.com/css2?family=Instrument+Serif&display=swap';
const FONT_DISPLAY_ITALIC =
	'https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@1&display=swap';
const FONT_MONO = 'https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@500&display=swap';

const TTF_HEADERS = {
	'User-Agent':
		'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_5) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27',
};

async function loadFontFromGoogle(url: string): Promise<ArrayBuffer> {
	const css = await (await fetch(url, { headers: TTF_HEADERS })).text();
	const match = css.match(/src:\s*url\((https:[^)]+)\)\s*format\('truetype'\)/);
	if (!match) {
		throw new Error(`Could not locate truetype font binary in CSS for ${url}`);
	}
	return await (await fetch(match[1] as string)).arrayBuffer();
}

export default async function OpengraphImage() {
	const ink = '#0B0B0B';
	const bone = '#F4EDE3';
	const clay = '#C8854A';
	const iron = '#3A3A3A';

	const [serif, serifItalic, mono] = await Promise.all([
		loadFontFromGoogle(FONT_DISPLAY),
		loadFontFromGoogle(FONT_DISPLAY_ITALIC),
		loadFontFromGoogle(FONT_MONO),
	]);

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
				fontFamily: 'IBM Plex Mono',
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
					display: 'flex',
				}}
			>
				ikavery · pre-alpha
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
						fontSize: 152,
						lineHeight: 0.96,
						letterSpacing: -6,
						color: ink,
						fontFamily: 'Instrument Serif',
					}}
				>
					Threshold-signed
				</div>
				<div
					style={{
						fontSize: 152,
						lineHeight: 0.96,
						letterSpacing: -6,
						color: iron,
						fontStyle: 'italic',
						fontFamily: 'Instrument Serif',
					}}
				>
					key custody.
				</div>
				<div
					style={{
						marginTop: 32,
						fontSize: 22,
						color: iron,
						fontFamily: 'IBM Plex Mono',
						display: 'flex',
					}}
				>
					k-of-n MPC via Ika · live on Sui &amp; Solana · sui.ikavery.com · solana.ikavery.com
				</div>
			</div>
		</div>,
		{
			...size,
			fonts: [
				{ name: 'Instrument Serif', data: serif, style: 'normal', weight: 400 },
				{
					name: 'Instrument Serif',
					data: serifItalic,
					style: 'italic',
					weight: 400,
				},
				{ name: 'IBM Plex Mono', data: mono, style: 'normal', weight: 500 },
			],
		},
	);
}
