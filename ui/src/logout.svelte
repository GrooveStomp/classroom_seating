<script>
  import { user } from './stores.js';

  async function logout() {
      const res = await fetch('http://localhost:9000/logout', {
          method: 'GET',
          headers: {
              'Content-Type': 'application/json',
              'Accept': 'application/json',
              'X-Auth-Token': $user.authToken
          },
      })

      if (res.ok) {
          user.set({})
      }
  }
</script>

<div class="logout">
  <h1>Logout</h1>
  <button on:click={logout}>Logout</button>
</div>

<style>
	.logout {
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
		.logout {
			max-width: none;
		}
	}
</style>
