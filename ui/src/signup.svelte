<script>
  let formData = {
      username: '',
      password: '',
  };

  async function login() {
      await fetch('http://localhost:9000/users', {
          method: 'POST',
          headers: {
              'Content-Type': 'application/json',
              'Accept': 'application/json'
          },
          body: JSON.stringify({ username: formData.username, password: formData.password })
      })
          .then(r => r.json())
          .then(data => {
              document.getElementById("signup").appendChild("<p>Success!</p>")
          });
  }
</script>

<div class="signup" id="signup">
  <h1>Signup</h1>
  <p>
    Username:
    <input bind:value={formData.username}>
  </p>
  <p>
    Password:
    <input type=password bind:value={formData.password}>
  </p>
  <button on:click={login}>Signup</button>
</div>

<style>
	.signup {
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
		.signup {
			max-width: none;
		}
	}
</style>
