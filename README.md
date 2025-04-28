# nutanix-prometheus-exporter

A python based prometheus exporter that extracts metrics from the Nutanix API or the Redfish API from out-of-band management modules of hardware nodes in a Nutanix cluster.  
These metrics can then be scraped by any prometheus compatible product and leveraged in a dashboarding application with a compatible data source type (exp: a Prometheus server or InfluxDB instance scrapes the metrics and is then configured as a data source in Grafana).

The exporter has 3 differention mode of operations:  

1. *legacy*: this mode targets a single Prism element OR Prism Central and extracts performance metrics from the Nutanix API using v1, v2 and v3 endpoints.  When targeting Prism element, you can also retrieve storage containers, vms and IPMI metrics using environment variables to enable or disable the collection for these entity types.  When targeting Prism Central, you get in return a count for different entity types (vm count, vg count, vdisk count, etc...).  
2. *redfish*: this mode targets a bunch of IPMI interfaces on hardware nodes and collects power consumption and thermal metrics.  
3. *v4*: this mode is **not yet functional** and is work in progress.  It targets a Prism Central instance and collects metrics from all available entities using v4 API calls and multi-threading for better performance.  

> [!WARNING] 
> v4 mode of operations is not yet functional and is a work in progress.  Do not use for now.

For available environment variables that are used to control the behavior and configuration of this prometheus exporter, review the Dockerfile content.

## Building the container

From the **build** directory, run (if using podman, rename `dockerfile` to `Dockerfile` and replace `docker` with `podman`):

 `docker build -t nutanix-prometheus-exporter .`

> [!TIP] 
> It is recommended to tag your image build with the correct processor architecture you are building it for (such as Linux/arm64 or Linux/amd64).  With podman this can be achieved with the --platform parameter when using the build command.

 ## Running the container

 Available environment variables are listed in the `dockerfile` file in the **build** directory.

 Example of docker command line (if using podman, replace `docker` with `podman`):

```sh
docker run -d --name nutanix-exporter-1 -p 8000:8000 -e PRISM=192.168.0.10 -e PRISM_USERNAME=admin -e PRISM_SECRET=mysecret nutanix-prometheus-exporter
```
> [!IMPORTANT] 
> The above command assumes that you have previsouly created a secret called PRISM_SECRET.

 You can then open your browser to [http://localhost:8000](http://localhost:8000) to verify metrics are being published correctly.

 You can use `docker logs nutanix-exporter-1` to troubleshoot issues in the container (if using podman, replace `docker` with `podman`).


 ## Building a demo environment

 1. Build and run the container as documented above.
 2. Now deploy an influxdb container:  
    ```sh
    podman pull influxdb  
    podman volume create influxdb-volume  
    podman run --name influxdb -d -p 8086:8086 --volume influxdb-volume:/var/lib/influxdb2 influxdb:latest  
    podman exec influxdb influx setup --bucket MyPrism --org Nutanix --password PASSWORD --username USERNAME --force  
    ```
 3. Deploy a grafana container:  
    ```sh
    podman pull grafana/grafana  
    podman volume create grafana-volume  
    podman run --name grafana -d -p 3000:3000 --volume grafana-volume:/var/lib/grafana grafana:latest  
    ```
 1. Connect to influxdb [http://localhost:8086](http://localhost:8086) and add a scraper pointing to http://<your_ip_address>:8000 to feed data in the MyPrism bucket.  You can check after 10 seconds that your bucket is receving data.  Also create an API token called grafana and copy the API key to your clipboard.  Also grab the id of the MyPrism bucket from the influxdb UI.
 2. Connect to Grafana [http://localhost:3000](http://localhost:3000) and select your influxdb as a data source. Use your IP address in the target URL on port 8086, paste the database id in database, and paste the API token in password.  When you test the connection, if you do not get any measurements, try running the following commands in the influxdb container, then reconfigure the data source in grafana using Flux instead of InfluxQL as the query language:
    ```sh
    influx v1 dbrp create --bucket-id <bucket_id_for_MyPrism> --org Nutanix --db MyPrism --rp 1week --default
    influx v1 auth create --description grafana --org-id <your_org_id> --password <some_password> --skip-verify --username grafana --read-bucket <MyPrism_bucket_id>
    ```
    If you end up having to use the Flux query language, you can easily visualize data/metrics in the InfluxDB bucket explorer then look at the flux syntax in the script editor and copy/paste that code in Grafana.
 1. Build your dashboard