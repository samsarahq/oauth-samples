export default function Home() {
  return (
    <div className="flex flex-col items-center justify-center min-h-screen p-8">
      <h1 className="text-3xl font-bold mb-8">Welcome</h1>
      <a
        href="/authorize"
        className="rounded-full bg-foreground text-background px-6 py-3 hover:bg-[#383838] transition-colors"
      >
        Connect to Samsara
      </a>
    </div>
  );
}
