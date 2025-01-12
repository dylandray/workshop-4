import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT } from "../config";

export async function simpleOnionRouter(nodeId: number) {

  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());

  const lastReceivedMessage = null;
  const lastReceivedDecryptedMessage = null;
  const lastMessageDestination = null;
  
  onionRouter.get("/status/", (req, res) => {
    res.send("live");
  });

  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
    res.json({ result: lastReceivedMessage });
  });

  onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
    res.json({ result: lastReceivedDecryptedMessage });
  });

  onionRouter.get("/getLastMessageDestination", (req, res) => {
    res.json({ result: lastMessageDestination });
  });

  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {

    console.log(
      `Onion router ${nodeId} is listening on port ${
        BASE_ONION_ROUTER_PORT + nodeId
      }`

    );
  });

  return server;
  
}
