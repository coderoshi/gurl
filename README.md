# Glass Curl (gurl)

First launch the webapp then login to the website. Export the GURL_TOKEN and GURL_USER_ID the webapp gives you.

## Webapp

Setup Google API, then export GURL_CLIENT_ID and GURL_CLIENT_SECRET env vars. Deploy the web app. Point the gurl URL at the webapp base url.

## Commandline

`gurl resource curl_args`

### Example

Creating a timeline item

`gurl timeline -XPOST -d '{"text":"Hello Glass!"}'`
