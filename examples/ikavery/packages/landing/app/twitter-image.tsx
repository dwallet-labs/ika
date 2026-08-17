import { ImageResponse } from 'next/og';

export const alt = 'ikavery · threshold-signed key custody · live on Sui and Solana';
export const size = { width: 1200, height: 675 };
export const contentType = 'image/png';

const FONT_DISPLAY = 'https://fonts.googleapis.com/css2?family=Instrument+Serif&display=swap';
const FONT_DISPLAY_ITALIC =
	'https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@1&display=swap';
const FONT_BODY = 'https://fonts.googleapis.com/css2?family=Hanken+Grotesk:wght@500&display=swap';
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

export default async function TwitterImage() {
	const ink = '#0B0B0B';
	const bone = '#F4EDE3';
	const clay = '#C8854A';
	const iron = '#3A3A3A';
	const mist = '#D8D2C5';

	const [serif, serifItalic, body, mono] = await Promise.all([
		loadFontFromGoogle(FONT_DISPLAY),
		loadFontFromGoogle(FONT_DISPLAY_ITALIC),
		loadFontFromGoogle(FONT_BODY),
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
	const cell = 18;

	return new ImageResponse(
		<div
			style={{
				width: '100%',
				height: '100%',
				display: 'flex',
				flexDirection: 'column',
				background: bone,
				padding: '64px 80px',
				fontFamily: 'Hanken Grotesk',
				position: 'relative',
			}}
		>
			<div
				style={{
					position: 'absolute',
					top: 64,
					right: 80,
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
					display: 'flex',
					flexDirection: 'column',
					gap: 12,
				}}
			>
				<div
					style={{
						fontSize: 22,
						letterSpacing: 6,
						textTransform: 'uppercase',
						color: clay,
						fontFamily: 'IBM Plex Mono',
						display: 'flex',
						alignItems: 'center',
						gap: 16,
					}}
				>
					<span
						style={{
							display: 'block',
							width: 10,
							height: 10,
							background: clay,
							borderRadius: 999,
						}}
					/>
					Now live · Sui · Ika · Solana
				</div>
				<div
					style={{
						fontSize: 15,
						color: iron,
						fontFamily: 'IBM Plex Mono',
						letterSpacing: 0,
						display: 'flex',
						flexDirection: 'column',
						gap: 2,
						maxWidth: 720,
					}}
				>
					<span>Pre-alpha · not audited · no warranty.</span>
					<span>Sui testnet &amp; Solana devnet only. Use at your own risk.</span>
				</div>
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
						fontSize: 200,
						lineHeight: 0.94,
						letterSpacing: -8,
						color: ink,
						fontFamily: 'Instrument Serif',
					}}
				>
					Keys kept
				</div>
				<div
					style={{
						fontSize: 200,
						lineHeight: 0.94,
						letterSpacing: -8,
						color: iron,
						fontStyle: 'italic',
						fontFamily: 'Instrument Serif',
					}}
				>
					by quorum.
				</div>

				<div
					style={{
						marginTop: 36,
						paddingTop: 18,
						borderTop: `1px solid ${mist}`,
						display: 'flex',
						alignItems: 'baseline',
						justifyContent: 'space-between',
						gap: 24,
					}}
				>
					<div
						style={{
							fontSize: 22,
							color: iron,
							fontFamily: 'IBM Plex Mono',
							letterSpacing: 0,
						}}
					>
						sui.ikavery.com&nbsp;&nbsp;·&nbsp;&nbsp;solana.ikavery.com
					</div>
					<div
						style={{
							fontSize: 18,
							letterSpacing: 6,
							textTransform: 'uppercase',
							color: clay,
							fontFamily: 'IBM Plex Mono',
						}}
					>
						ikavery.com →
					</div>
				</div>
			</div>
		</div>,
		{
			...size,
			fonts: [
				{
					name: 'Instrument Serif',
					data: serif,
					style: 'normal',
					weight: 400,
				},
				{
					name: 'Instrument Serif',
					data: serifItalic,
					style: 'italic',
					weight: 400,
				},
				{ name: 'Hanken Grotesk', data: body, style: 'normal', weight: 500 },
				{ name: 'IBM Plex Mono', data: mono, style: 'normal', weight: 500 },
			],
		},
	);
}
