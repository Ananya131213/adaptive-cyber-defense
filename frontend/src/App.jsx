const workstreams = [
  'Detection',
  'Correlation',
  'Explainability',
  'Response simulation',
];

export default function App() {
  return (
    <main>
      <header>
        <p>Security operations · Hackathon build</p>
        <h1>Adaptive Cyber Defense</h1>
        <p>
          Threat hunting across authentication, endpoint, network, and cloud
          activity.
        </p>
      </header>
      <section aria-labelledby="workstreams-heading">
        <h2 id="workstreams-heading">Platform workstreams</h2>
        <ul>
          {workstreams.map((workstream) => (
            <li key={workstream}>{workstream}</li>
          ))}
        </ul>
      </section>
    </main>
  );
}