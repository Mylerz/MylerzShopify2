import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router";
import {
  Filters,
  Card,
  ResourceList,
  TextStyle,
  Stack,
  ResourceItem,
  Heading,
  Button,
  ExceptionList,
  ProgressBar,
} from "@shopify/polaris";
// import Router from "next/router";
// import { removeAllListeners } from "process";
// import Cookies from "js-cookie";
// import { useNavigate } from '@shopify/app-bridge-react';

import { userLoggedInFetch } from "../App";
import { useAppBridge } from "@shopify/app-bridge-react";
import { db } from '../db'

//localForage.setDriver(localForage.INDEXEDDB);


const FulfilledOrders = () => {
  const [orders, setOrders] = useState([]);
  const [selectedOrdersIDs, setSelectedOrdersIDs] = useState([]);
  const [processing, setProcessing] = useState(false);
  const [currentlyProcessing, setCurrentlyProcessing] = useState(0);
  const [allOrders, setAllOrders] = useState([]);
  const [queryValue, setQueryValue] = useState(null);
  const navigate = useNavigate()
  const app = useAppBridge();
  const fetch = userLoggedInFetch(app);


  // const [firstPageUrl, setFirstPageUrl] = useState(
  //   // `https://${Cookies.get(
  //   //   "shopOrigin"
  //   // )}/admin/api/2022-01/orders.json?status=any&limit=150`
  //   ""
  // );
  const [nextPageUrl, setNextPageUrl] = useState("");


  const promotedBulkActions = [
    {
      content: "Bulk Print AWB",
      disabled: processing,
      onAction: () => {
        bulkPrintAwb(selectedOrdersIDs);
      },
    },
  ];

  const bulkActions = [
    {
      content: "Create Pickup Order",
      onAction: () => {
        createPickupOrder(selectedOrdersIDs);
      },
    },
  ];


  useEffect(() => {
    const loadOrdersAsync = async () => {
      await loadOrders("", true);
    };

    loadOrdersAsync();
  }, []);

  const loadOrders = async (url, isFirstCall) => {


    if (url != null) {

      console.log("loading Order")

      setProcessing(true);

      console.log(`Loading Orders: First Time? ${isFirstCall}`);

      let param = {
        param: "status",
        value: "any",
        url: url,
      };
      let response = await fetch("/api/orders", {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify(param),
      });
      const result = await response.json();

      let subOrders = result.data.orders.filter(
        (order) =>
          order.fulfillments[0] &&
          order.fulfillment_status == "fulfilled" &&
          order.fulfillments[0].tracking_company == "Mylerz"
      )
        .map(order => {
          // let refunded_line_items = order.refunds
          //   .map((refund) =>refund.refund_line_items.map(
          //       (refund_line_item) => refund_line_item.line_item
          //     )
          //   )
          //   .flat(2);

          // let current_line_items = order.line_items.filter(
          //   (line_item) =>
          //     !refunded_line_items.map((item) => item.id).includes(line_item.id)
          // );

          // order["line_items"] = current_line_items;

          let refunded_line_items = order.refunds
            .map((refund) => refund.refund_line_items).flat(2);


          let current_line_items = order.line_items.filter((line_item) => {
            let refunded_line_item = refunded_line_items.find(refund_item => refund_item.line_item_id == line_item.id);
            if (refunded_line_item && refunded_line_item.quantity == line_item.quantity) {
              return false
            }
            return true;
          }
          ).map(line_item => {
            let refunded_line_item = refunded_line_items.find(refund_item => refund_item.line_item_id == line_item.id);
            if (refunded_line_item) {
              line_item["quantity"] = line_item.quantity - refunded_line_item.quantity;
              return line_item
            }
            return line_item;
          });
          // this.log(order.name,current_line_items);

          order["current_line_items"] = current_line_items;

          return order;
        });

      if (isFirstCall) {
        setOrders(subOrders);
        setAllOrders(subOrders);
        setNextPageUrl(result.data.nextLink);
        // setFirstPageUrl(result.data.nextLink);
      } else {
        setOrders(orders.concat(subOrders));
        setAllOrders(allOrders.concat(subOrders));
        setNextPageUrl(result.data.nextLink);
        // setFirstPageUrl(result.data.nextLink);
      }
      setProcessing(false);

    }
  };


  const printAwb = async (id) => {

    try {

      setProcessing(true);


      const order = orders.find((order) => order.id == id);
      let trackingNumbers = order.fulfillments
        .filter((fulfillment) => fulfillment.status == "success")
        .map((fulfillment) => fulfillment.tracking_numbers)
        .flat(2);
      trackingNumbers = [...new Set(trackingNumbers)];
      let response = await fetch(`api/getAWB/`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ trackingNumbers: trackingNumbers, token: localStorage.getItem("access_token") }),
      });


      let result = await response.json();
      if (result.status == "success") {
        navigate("/pdf", { state: { awbList: result.AWB } });

      }
    } catch (error) {

      setProcessing(false);

    }
  };

  const bulkPrintAwb = async (selectedIds) => {

    try {


      setProcessing(true);

      console.log(selectedIds);
      const selectedOrders = orders.filter((order) =>
        selectedIds.includes(order.id)
      );
      let trackingNumbers = selectedOrders.flatMap((order) =>
        order.fulfillments
          .filter((fulfillment) => fulfillment.status == "success")
          .flatMap((fulfillment) => fulfillment.tracking_numbers)
      );
      trackingNumbers = [...new Set(trackingNumbers)];
      let response = await fetch(`api/getAWB/`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ trackingNumbers: trackingNumbers, token:localStorage.getItem("access_token") }),
      });


      let result = await response.json();
      if (result.status == "success") {
        navigate("/pdf", { state: { awbList: result.AWB } });

      }

    } catch (error) {

      setProcessing(false);
    }
  };

  const createPickupOrder = async (selectedIds) => {
    setProcessing(true);

    // console.log(selectedIds);
    const selectedOrders = orders.filter((order) =>
      selectedIds.includes(order.id)
    );
    let trackingNumbers = selectedOrders.flatMap((order) =>
      order.fulfillments
        .filter((fulfillment) => fulfillment.status == "success")
        .flatMap((fulfillment) => fulfillment.tracking_numbers)
    );
    trackingNumbers = [...new Set(trackingNumbers)];

    let response = await fetch(`api/createPickupOrder/`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ trackingNumbers: trackingNumbers, token:localStorage.getItem("access_token") }),
    });

    let result = await response.json();
    console.log(result);


    await attachPickupOrder(result);
    await loadOrders("", true);

    setCurrentlyProcessing(0);
    setSelectedOrdersIDs([])
    setProcessing(false);
  };

  const attachPickupOrder = async (result) => {

    let selectedOrders = orders.filter((order) =>
      selectedOrdersIDs.includes(order.id)
    );

    let pickupOrderPerPackage = {}

    result.PickupOrders.Value.forEach(pickupOrder => {
      if (pickupOrder.PickupOrderCode != null) {
        pickupOrder.PickupPackages.forEach(pack => pickupOrderPerPackage[pack.Barcode] = `PickupOrder: ${pickupOrder.PickupOrderCode}`)
      }
    })


    let pickupOrders = selectedOrders.map((order) => {

      let orderTracking = order.fulfillments
        .filter((fulfillment) => fulfillment.status == "success")
        .flatMap((fulfillment) => fulfillment.tracking_numbers)

      let uniquePackageBarCode = [...new Set(orderTracking)];

      let pickupOrderPerList = uniquePackageBarCode.map(packageBarcode => pickupOrderPerPackage[packageBarcode]);

      return pickupOrderPerList
    });


    for (let index = 0; index < selectedOrders.length; index++) {

      if (pickupOrders[index].some(x => x != undefined)) {


        console.log("PickupOrderIDs of Packages: ", pickupOrders[index])

        let response = await fetch(`api/order/attachPickupOrder/`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            orderID: selectedOrders[index].id,
            tags: selectedOrders[index].tags,
            pickupOrdersIDs: pickupOrders[index].filter(x => x != undefined)
          }),
        });

        let result = await response.json();
        console.log(result)
        // console.log(`Currently Processing Before: ${currentlyProcessing}`);
        // console.log(`Currently Processing After: ${currentlyProcessing}`);
      }

      setCurrentlyProcessing(currentlyProcessing => currentlyProcessing + 1);

    }

  };

  const handleFiltersQueryChange = (value) => {
    console.log("queryChange--->", value);
    setQueryValue(value);
    if (value !== "") {
      setOrders(
        allOrders.filter(
          (order) =>
            order.name.includes(value) ||
            order.created_at.includes(value) ||
            order.total_outstanding.includes(value) ||
            (order.shipping_address
              ? order.shipping_address.address1.includes(value)
              : false) ||
            order.line_items
              .map((item) => item.title)
              .join()
              .includes(value) ||
            order.tags.includes(value)
        )
      );
    } else {
      setOrders(allOrders);
    }
  };
  const handleQueryValueRemove = () => {
    setQueryValue(null);
    setOrders(allOrders);
  };

  return (
    <Card>
      {processing ? (
        <div>
          <ProgressBar
            progress={(currentlyProcessing / selectedOrdersIDs.length) * 100}
          />
          Processed Orders: {currentlyProcessing} / {selectedOrdersIDs.length}
        </div>
      ) : (
        <div></div>
      )}
      <Button
        plain
        onClick={() => loadOrders(nextPageUrl, false)}
      >
        Load More{" "}
      </Button>
      <ResourceList
        resourceName={{ singular: "order", plural: "orders" }}
        items={orders}
        selectedItems={selectedOrdersIDs}
        promotedBulkActions={promotedBulkActions}
        bulkActions={bulkActions}
        onSelectionChange={setSelectedOrdersIDs}
        renderItem={(item) => {
          const {
            id,
            name,
            created_at,
            total_outstanding,
            line_items,
            shipping_address,
            tags,
            current_line_items
          } = item;
          const { address1 } = shipping_address;
          return (
            <ResourceItem id={id}>
              <Stack vertical>
                <Stack>
                  <Stack.Item>
                    <Heading>Order {name} </Heading>
                  </Stack.Item>
                  <Stack.Item>
                    <TextStyle>{created_at}</TextStyle>
                  </Stack.Item>
                  <Stack.Item fill>
                    <TextStyle>{total_outstanding}</TextStyle>
                  </Stack.Item>
                  <Stack.Item>
                    <Button primary onClick={() => printAwb(id)}>
                      Print AWB
                    </Button>
                  </Stack.Item>
                </Stack>
                <TextStyle> {address1}</TextStyle>
                <Stack>
                  <Stack.Item fill>
                    <ExceptionList
                      items={current_line_items.map((lineItem) => {
                        return {
                          description: `Title: ${lineItem.title},  Quantity: ${lineItem.quantity}`,
                        };
                      })}
                    />
                  </Stack.Item>
                  <Stack.Item>
                    <ExceptionList
                      items={tags.split(",").map((tag) => {
                        return { description: `${tag}` };
                      })}
                    />
                  </Stack.Item>
                </Stack>
              </Stack>
            </ResourceItem>
          );
        }}
        filterControl={
          <Filters
            queryValue={queryValue}
            queryPlaceholder="Filter Orders"
            filters={[]}
            onQueryChange={handleFiltersQueryChange}
            onQueryClear={handleQueryValueRemove}
            onClearAll={handleQueryValueRemove}
          />
        }
        loading={processing}
      ></ResourceList>

      <Button plain onClick={() => loadOrders(nextPageUrl, false)}>
        Load More
      </Button>
    </Card>
  );
};

export default FulfilledOrders