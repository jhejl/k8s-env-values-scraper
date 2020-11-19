# k8s Deployment ENV scraper

Simple tool to scrape k8s deployments for Secrets and ConfigMaps that are being passed as ENV values into the containers. The tool scrapes the values and searches for URIs, IPs and DOMAIN names, so one may quickly figure out the external resources to be available for the service during the deployment phase.

**WARNING:** It's simple tool ... nobody forces you to use it.
