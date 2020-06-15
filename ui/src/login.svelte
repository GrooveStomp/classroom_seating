<script>
  import { user } from './stores.js';

  let formData = {
      username: '',
      password: '',
      authToken: ''
  };

  async function login() {
      await fetch('http://localhost:9000/login', {
          method: 'POST',
          headers: {
              'Content-Type': 'application/json',
              'Accept': 'application/json'
          },
          body: JSON.stringify({ username: formData.username, password: formData.password })
      })
          .then(r => r.json())
          .then(data => {
              user.set({
                  username: formData.username,
                  password: formData.Password,
                  authToken: data['auth_token']
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
