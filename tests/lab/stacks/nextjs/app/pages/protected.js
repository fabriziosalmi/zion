// The canary: seen only by a request that passed the authorization check.
export default function Protected() {
  return <p>PROTECTED-CANARY</p>;
}
