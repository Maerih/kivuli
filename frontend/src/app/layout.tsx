import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = {
  title: "Kivuli · Dark web threat intelligence",
  description: "Threat intelligence console",
  icons: { icon: "/favicon.svg" },
  robots: { index: false, follow: false },
};

// Applied before first paint so a stored theme choice never flashes.
const themeScript = `try{var t=localStorage.getItem("kivuli-theme");if(t==="dark"||t==="light")document.documentElement.dataset.theme=t}catch(e){}`;

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
      </head>
      <body>{children}</body>
    </html>
  );
}
