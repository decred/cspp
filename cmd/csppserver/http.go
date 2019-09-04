package main

import (
	"bytes"
	"html/template"
	"net/http"
	"path"
	"time"
)

type indexHandler struct {
	ServerName string
	Address    string
	Epoch      time.Duration
	SelfSigned []byte
}

func (h *indexHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if len(h.SelfSigned) != 0 && r.URL.Path == "/"+h.ServerName+".pem" {
		w.Header().Add("Expires", time.Now().Add(365*24*time.Hour).Format(time.RFC1123))
		http.ServeContent(w, r, path.Base(r.URL.Path), time.Time{}, bytes.NewReader(h.SelfSigned))
		return
	}
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	indexTmpl.Execute(w, h)
}

var indexTmpl = template.Must(template.New("index").Parse(`<!DOCTYPE html>
<html lang="en">
{{define "service-config"}}--csppserver={{.Address}}{{if .SelfSigned}} \
  --csppserver.ca={{.ServerName}}.pem{{end}}{{end}}
<head>
<title>Decred CoinShuffle++</title>
<meta name="viewport" content="width=device-width">
<link rel=icon href=data:,>
<style>
main {
        max-width: 80ch;
        padding: 2ch;
        line-height: 1.4;
        margin: auto;
        font-family: sans-serif;
}
</style>
</head>

<body>
<main>
<h1>Decred CoinShuffle++</h1>

<p>This service provides CoinShuffle++ mixing to create Decred CoinJoin
transactions with other users of the server.  It acts as a coordination point
and provides optimized polynomial factorization to improve mix times.  The
server does not know which mixed outputs in a successfully-created CoinJoin
belong to which peer.</p>

<p>The mixing epoch is {{.Epoch}}.</p>

{{if .SelfSigned}}
<p>This server is configured with a self-signed TLS certificate.
It must be saved and referenced by the <code>dcrwallet</code> config.
<a href="/{{.ServerName}}.pem" download>Click here</a> to download
and see below for config examples.</p>
{{end}}

<h2>Mixed ticket buying</h2>

<p>Mixed ticket buying uses CoinShuffle++ to anonymize outputs of split
transactions, which are spent to create ticket purchases.  Voting rights and
commitment outputs must be assigned to unused and unique addresses of accounts
and not single addresses to prevent address reusage.</p>

<p>Solo stakers are recommended to use two wallets to separate ticket buying and
voting, due to requirements of the voting wallet being always unlocked and
highly available.  An extended public key must be exported from the voting
wallet (using <code>getmasterpubkey</code>) and imported by the ticket buying
wallet (using <code>importxpub</code>).</p>

<p>Use the following options for a mixed solo ticket buyer which continues to
buy more tickets from the mixed account as outputs mature:</p>

<pre>
$ dcrwallet {{template "service-config" .}} \
  --enableticketbuyer --purchaseaccount=mixed --mixedaccount=mixed/1 \
  --changeaccount=unmixed --ticketbuyer.votingaccount=voting --mixchange
</pre>

<h3>Converting from an unmixed ticket buyer</h3>

Solo stakers wishing to convert from an unmixed solo ticket buying setup to a
mixed buyer can use two ticket buying wallets simultaneously, with a setup to
slowly mix funds from the existing buyer (buyer1) to the new mixed buyer
(buyer2).

Each ticket buyer must be provisioned with a unique voting xpub:

<pre>
voter$ dcrctl --wallet createnewaccount voting1
voter$ dcrctl --wallet createnewaccount voting2
voter$ dcrctl --wallet getmasterpubkey voting1
<em>voting1-xpub</em>
voter$ dcrctl --wallet getmasterpubkey voting2
<em>voting2-xpub</em>
buyer1$ dcrctl --wallet importxpub voting <em>voting1-xpub</em>
buyer2$ dcrctl --wallet importxpub voting <em>voting2-xpub</em>
</pre>

In addition, the mixed account xpub of the mixed ticket buyer must be imported
by buyer1:

<pre>
buyer2$ dcrctl --wallet getmasterpubkey mixed
<em>mixed-xpub</em>
buyer1$ dcrctl --wallet importxpub mixed <em>mixed-xpub</em>
</pre>

The mixed ticket buying wallet may use the setup from the previous section.  The
old wallet must be configured sligtly differently:

<pre>
buyer1$ dcrwallet {{template "service-config" .}} \
  --enableticketbuyer --purchaseaccount=default --mixedaccount=mixed/0 \
  --ticketsplitaccount=default --changeaccount=unmixed
  --ticketbuyer.votingaccount=voting --mixchange
</pre>

Note these differences:

<ul>
  <li>
  <strong><code>--mixedaccount=mixed/0</code></strong> - The unmixed wallet must
  use the external (not internal) branch of the mixed account to avoid address
  reuseage problems arising from two wallets simultaneously deriving from the same
  branch.
  </li>

  <li>
  <strong><code>--ticketsplitaccount=default</code></strong> - Unless this is set,
  the mixed account and branch will be used derive a fresh address for the mix.
  However, this would create issues when publishing a ticket, because the unmixed
  wallet does not have the required private key (mixed account is an imported xpub).
  This option must be set to a derived account with private keys, such as the
  purchasing source account.
  </li>
</ul>

<h2>Change mixing and non-staking</h2>

<p>Change outputs in the CoinJoin are not anonymous, and can easily be traced
back to the set of inputs used during the mix.  A dedicated unmixed account for
CoinShuffle++ change is required, and it is not safe to spend change with other
outputs in any transaction, including other mixes.  To remedy this,
<code>dcrwallet</code> provides a change mixing feature to create smaller mixed
outputs of standard values and never submitting more than a single change output
to the mixer in a request.

<p>These features are enabled with the following config:</p>

<pre>
$ dcrwallet {{template "service-config" .}} \
  --mixedaccount=mixed/1 --changeaccount=unmixed --mixchange
</pre>

<p>Alternatively, the <code>mixaccount</code> JSON-RPC may be used instead of
the <code>--mixchange</code> option to mix single outputs
from the account without leaving the wallet persistently unlocked.</p>

<p>Non-stakers are able to use this mechanism to mix received funds.  Use the
unmixed account to provide receiving addresses and mix the account as if it was
CoinShuffle++ change.</p>

<h2>Address reusage</h2>

<p>Address reusage strips the anonymity provided by CoinShuffle++.  It is
imperative that addresses are never reused and that extended public keys of
mixed and voting accounts are not revealed to other parties.</p>

</main>
</body>
</html>`))
