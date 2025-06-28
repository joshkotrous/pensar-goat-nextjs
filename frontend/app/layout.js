export const metadata = {
  title: 'SAST Benchmark App',
  description: 'Testing SAST scanner accuracy'
}

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}
