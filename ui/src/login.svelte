<script>
  import * as jsrs from 'jsrsasign';
  import { v4 as uuid } from 'uuid';
  import { user } from './stores.js';

  let formData = {
      username: '',
      password: '',
      authToken: ''
  };

  async function login() {
      var clientToken = uuid();
      user.update(o => o.clientToken = clientToken);

      await fetch('http://localhost:9000/login', {
          method: 'POST',
          headers: {
              'Content-Type': 'application/json',
              'Accept': 'application/json',
              'X-Client-Token': clientToken
          },
          body: JSON.stringify({ username: formData.username, password: formData.password })
      })
          .then(r => r.json())
          .then(data => {
              var jwt = data['jwt'];

              var isValid = jsrs.jws.JWS.verifyJWT(jwt, clientToken, { alg: ["HS256"] });
              alert("Is JWT valid?: " + isValid)

              var parts = jwt.split(".")
              var header = jsrs.jws.JWS.readSafeJSONString(b64utoutf8(parts[0]));
              var payload = jsrs.jws.JWS.readSafeJSONString(b64utoutf8(parts[1]));

              alert("Encrypted JWT token: " + payload['aud']);

              user.update(function(object) {
                  object.username = formData.username;
                  object.password = formData.password;
              });
          });

      console.log($user);
  }
</script>

<div class="login">
  <h1>Login</h1>
  <p>
    Username:
    <input bind:value={formData.username}>
  </p>
  <p>
    Password:
    <input type=password bind:value={formData.password}>
  </p>
  <button on:click={login}>Login</button>
</div>

<style>
	.login {
		text-align: center;
		padding: 1em;
		max-width: 240px;
		margin: 0 auto;
	}

	h1 {
		color: #ff3e00;
		text-transform: uppercase;
		font-size: 4em;
		font-weight: 100;
	}

	@media (min-width: 640px) {
		.login {
			max-width: none;
		}
	}
</style>
