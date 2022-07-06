import warehouseContext from "./warehouseContext";
import React, { useState, useEffect, useContext } from "react";

import { userLoggedInFetch } from "../App";
import { useAppBridge, useNavigate } from "@shopify/app-bridge-react";
import { useNavigate as useReactNavigate } from "react-router";
import {
  InlineError,
  Filters,
  Card,
  ResourceList,
  TextStyle,
  Stack,
  ResourceItem,
  Heading,
  Button,
  ExceptionList,
  Select,
  Banner,
  Badge,
  ProgressBar,
  Modal
} from "@shopify/polaris";
import { format } from "date-fns";


import { db } from '../db'
//localForage.setDriver(localForage.INDEXEDDB);


const OrderList = () => {


  const [selectedWarehouseForBulk, setSelectedWarehouseForBulk] = useState("");
  const [isSingleWarehouse, setIsSingleWarehouse] = useState(false);
  // const [warehouses, setWarehouses] = useState([]);
  const [selectedOrdersNotReady, setSelectedOrdersNotReady] = useState(false);
  const [orders, setOrders] = useState([]);
  const [allOrders, setAllOrders] = useState([]);
  const [nextPageUrl, setNextPageUrl] = useState("");
  // const [pageOrders, setPageOrders] = useState([]);
  // const [activePage, setActivePage] = useState(1);
  // const [numberOfPages, setNumberOfPages] = useState(0);
  const [selectedNeighborhood, setSelectedNeighborhood] = useState({});
  const [selectedCities, setSelectedCities] = useState({});
  const [selectedOrders, setSelectedOrders] = useState([]);
  const [failedToFetchZones, setFailedToFetchZones] = useState(false);
  const [previousFailedOrder, setPreviousFailedOrder] = useState([]);
  const [currentlyFulfilledOrder, setCurrentlyFulfilledOrder] = useState(0);
  const [totalOrdersToFulfilling, setTotalOrdersToFulfilling] = useState(0);
  const [fulfillmentResult, setFulfillmentResult] = useState({
    isFulfillmentRequested: false,
    isError: false,
    Message: "",
    AWB: null,
  });
  const [processing, setProcessing] = useState(false);
  const [queryValue, setQueryValue] = useState(null);
  const [activeModal, setActiveModal] = useState(false);

  const [citiesOptions, setCitiesOptions] = useState([]);
  const [cityZoneObject, setCityZoneObject] = useState({});

  const [, updateState] = React.useState();
  const forceUpdate = React.useCallback(() => updateState({}), []);


  const navigate = useNavigate()
  const reactNavigate = useReactNavigate()
  const app = useAppBridge();
  const fetch = userLoggedInFetch(app);

  useEffect(() => {
    const componentDidMount = async () => {
      let warehouses = await getWarehouses();

      if (warehouses.length == 1) {
        setSelectedWarehouseForBulk(warehouses[0]);
        setIsSingleWarehouse(true);
      }

      let warehouseOptionList = [
        { label: "Select Warehouse", value: "", disabled: true },
      ];

      warehouseOptionList = [
        ...warehouseOptionList,
        ...warehouses.map((warehouse) => {
          return { label: warehouse, value: warehouse };
        }),
      ];

      updateWarehouseOptions(warehouseOptionList);

      console.log(`warehouseOptions:${warehouseOptions}`);

      getCityZoneList();


      await loadOrders("", true);

      let cities = {};
      orders.forEach((order) => {
        cities[order.id] = null;
      });

      setSelectedCities(cities);

    };

    componentDidMount();
  }, []);


  const { orderItemWarehouse, updateOrderItemWarehouse, warehouseOptions, updateWarehouseOptions } = useContext(warehouseContext)

  const handleFiltersQueryChange = (value) => {
    setQueryValue(value);

    if (value !== "") {
      let filteredOrders = allOrders.filter(
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
      );
      setOrders(filteredOrders);

    } else {
      setOrders(allOrders);
    }
  };
  const handleQueryValueRemove = () => {
    setQueryValue(null);
    setOrders(allOrders);
  };
  const handleFiltersClearAll = () => {
    setQueryValue(null);

    setOrders(allOrders);
  };

  const selectNeighborhood = (neighborhood, id) => {
    let neighborhoods = selectedNeighborhood;
    neighborhoods[id].neighborhood = neighborhood;
    setSelectedNeighborhood(neighborhoods);
    forceUpdate();

    // e.preventDefault()
  }
  const selectCity = (city, id) => {
    let cities = selectedCities;
    let neighborhoods = selectedNeighborhood;
    cities[id] = city;
    if (cityZoneObject[city].length != 1) {
      neighborhoods[id].neighborhood = "";
    } else {
      neighborhoods[id].neighborhood = cityZoneObject[city][0].value;
    }
    neighborhoods[id].neighborhoodOptions = cityZoneObject[city];
    neighborhoods[id].isCitySelected = true;

    setSelectedCities(cities);
    setSelectedNeighborhood(neighborhoods)

     forceUpdate();

  }
  const viewOrderDetails = (url) => {
    reactNavigate(url);
  }

  const getZones = async (addressList) => {
    let response = await fetch("api/getZones", {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        addressList: addressList,
        token: localStorage.getItem("access_token"),
      }),
    });

    let result = await response.json();

    // console.log(result);
    if (result.status === "success") {
      return result.Zones;
    } else {
      return [];
    }
  };


  const getWarehouses = async () => {
    let response = await fetch("api/warehouses", {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        token: localStorage.getItem("access_token"),
      }),
    });

    let result = await response.json();
    //console.log(result);

    if (result.status === "success") {
      return result.Warehouses;
    } else if (
      result.Error == "Authorization has been denied for this request."
    ) {

      navigate("/login");
    } else {
      return [];
    }
  };


  const getCityZoneList = async () => {
    let response = await fetch("api/getCityZoneList");

    let result = await response.json();

    if (result.status === "success") {
      let citiesOp = result.Cities.map((city) => {
        return { label: city["EnName"], value: city["EnName"] };
      });
      let cityNeighborhoodObject = ProcessCityZoneList(result);

      setCityZoneObject(cityNeighborhoodObject);
      setCitiesOptions(citiesOp);
    }
  };

  const ProcessCityZoneList = (result) => {
    let cityNeighborhoodObject = {};
    result.Cities.forEach((city) => {
      let zoneObject = city["Zones"].map((zone) => {
        return { label: zone["EnName"], value: zone["Code"] };
      });
      cityNeighborhoodObject[city["EnName"]] = zoneObject;
    });

    return cityNeighborhoodObject;
  };

  const missingZones = (selectedOrdersToCheckMissingZones) => {
    return selectedOrdersToCheckMissingZones.some((order) => !order.shipping_address.city);
  };

  const loadOrders = async (url, isFirstCall) => {


    if (url != null) {
      setProcessing(true);

      let param = {
        param: "fulfillment_status",
        value: "unfulfilled",
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
      console.log(result);
      result.data.orders = result.data.orders.filter(
        (order) => order.fulfillment_status != "fulfilled"
      );

      let neighborhoods = {};
      result.data.orders.forEach((order) => {
        neighborhoods[order.id] = getOrderState(order);
      });


      let newOrders = result.data.orders.map((order) => {
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
        // log(order.name,current_line_items);

        order["current_line_items"] = current_line_items;

        return order;
      });


      if (isFirstCall) {
        setNextPageUrl(result.data.nextLink);
        setSelectedNeighborhood(neighborhoods);
        setAllOrders(newOrders);
        setOrders(newOrders);
      } else {
        setNextPageUrl(result.data.nextLink);
        setSelectedNeighborhood({
          ...selectedNeighborhood,
          ...neighborhoods,
        });
        setAllOrders(allOrders.concat(...newOrders));
        setOrders(orders.concat(...newOrders));
      }

      setProcessing(false);

    }
  };

  const setSelectedOrdersAndUpdateOrderItemWarehouse = (selectedOrdersToSetAndUpdate) => {
    setSelectedOrders(selectedOrdersToSetAndUpdate);

    let newOrderItemWarehouse = orders
      .filter((order) => selectedOrdersToSetAndUpdate.includes(order.id))
      .map((order) => {
        return order.current_line_items
          .filter(
            (item) =>
              !orderItemWarehouse
                .map((orderItem) => orderItem.itemId)
                .includes(item.variant_id)
          )
          .map((item) => {
            return {
              orderId: order.id,
              itemId: item.variant_id,
              warehouse: "",
              orderName: order.name,
            };
          });
      })
      .flat(Infinity);

    updateOrderItemWarehouse(newOrderItemWarehouse);


  };



  const fulfillOrders = async (ordersList, orderItemWarehouseList) => {
    log("fulfillOrders 1: ", ordersList)


    let data = {
      orders: ordersList,
      token: localStorage.getItem("access_token"),
      orderItemWarehouseList: orderItemWarehouseList,
    };
    let response = await fetch(`api/order/fulfill/`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(data),
    });

    let result = await response.json();

    return result;
  };

  const markOrderAsFulfilled = async (order, barcodes) => {
    // console.log(`barcode in mark ${barcodes}`)
    let data = { order: order, barcodes: barcodes, token: localStorage.getItem("access_token") };
    let response = await fetch(`api/order/markAsFulfilled/`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(data),
    });

    let result = await response.json();

    return result;
  };

  const startFulfillmentProcess = async (selectedOrdersToFulfill) => {

    let addressList = selectedOrdersToFulfill.map((order) =>
      order.shipping_address ? order.shipping_address.address1 : ""
    );

    let addressZoneList = await getZones(addressList);

    log("startFulfillmentProcess 1: ", selectedOrdersToFulfill)


    selectedOrdersToFulfill.forEach((order, index) => {
      order.closed_at = new Date();

      order.shipping_address
        ? (order.shipping_address.city = addressZoneList[index].m_Item2)
        : (order.shipping_address = {
          city: addressZoneList[index].m_Item2,
          address1: "",
        });

      if (!order.shipping_address.city) {
        order.shipping_address.city = selectedNeighborhood[
          order.id
        ].neighborhood
          ? selectedNeighborhood[order.id].neighborhood
          : null;
      }
    });

    log("startFulfillmentProcess 2: ", selectedOrdersToFulfill)

    if (missingZones(selectedOrdersToFulfill)) {
      let previouseSelectedOrders = selectedOrdersToFulfill;
      let newPreviousFailedOrders = [
        ...new Set([
          ...previousFailedOrder,
          ...selectedOrdersToFulfill
            .filter((order) => !order.shipping_address.city)
            .map((order) => order.id),
        ]),
      ];
      setSelectedOrders([]);
      setFailedToFetchZones(true);
      setPreviousFailedOrder(newPreviousFailedOrders);

      log("startFulfillmentProcess 3: ", selectedOrdersToFulfill)
      setSelectedOrders(newPreviousFailedOrders);


      log("startFulfillmentProcess 3: ", newPreviousFailedOrders)
    } else {
      let doesAllItemsHasWarehouse = checkItemWarehouse(selectedOrdersToFulfill);

      if (isSingleWarehouse || doesAllItemsHasWarehouse) {
        let selectedOrderIds = selectedOrdersToFulfill.map(order => order.id);


        fulfill(selectedOrderIds);
      } else {
        openModal();
      }

    }


  };

  const getAWB = async (trackingNumbers) => {
    trackingNumbers = [...new Set(trackingNumbers)]
    let data = { trackingNumbers: trackingNumbers, token: localStorage.getItem("access_token") };
    let response = await fetch(`api/getAWB/`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(data),
    });

    let result = await response.json();

    return result;
  }

  const fulfillByyMylerz = async (id) => {
    const order = orders.find((order) => order.id == id);
    // console.log(order);

    log("fulfillByyMylerz 1: ", order)

    setSelectedOrdersAndUpdateOrderItemWarehouse([id])

    log("fulfillByyMylerz 2: ", order)

    // console.log("fulfillByyMylerz 2: " + JSON.stringify(order));
    await startFulfillmentProcess([order]);
  }


  const validateOrder = (id) => {
    let order = selectedNeighborhood[id];
    // console.log("Order Status: "+order);
    let isReady = order?.readyForShipmentStatus;
    return isReady;
  }
  const getOrderState = (order) => {
    if (!order.shipping_address || !order.shipping_address?.address1) {
      return {
        neighborhood: null,
        isCitySelected: false,
        readyForShipmentStatus: false,
        readyForShipmentMessage: "missing shipping address",
      };
    } else if (!order.customer) {
      return {
        neighborhood: null,
        isCitySelected: false,
        readyForShipmentStatus: false,
        readyForShipmentMessage: "missing customer",
      };
    } else if (!order.shipping_address?.phone && !order.customer?.phone) {
      return {
        neighborhood: null,
        isCitySelected: false,
        readyForShipmentStatus: false,
        readyForShipmentMessage: "missing phone number",
      };
    } else if (!order.shipping_address.address1) {
      return {
        neighborhood: null,
        isCitySelected: false,
        readyForShipmentStatus: false,
        readyForShipmentMessage: "missing customer name",
      };
    } else {
      return {
        neighborhood: null,
        isCitySelected: false,
        readyForShipmentStatus: true,
        readyForShipmentMessage: "ready for shipment",
      };
    }
  };
  const openModal = () => {
    setActiveModal(true);
  }
  const closeModal = () => {
    setActiveModal(false);
    setSelectedOrdersAndUpdateOrderItemWarehouse([]);
  }

  const stampWarehouseToItem = (selectedOrdersToStamp) => {
    selectedOrdersToStamp.forEach((order) =>
      order.current_line_items.forEach((item) => {
        let orderItem = orderItemWarehouse.find(
          (orderItem) =>
            orderItem.orderId == order.id &&
            orderItem.itemId == item.variant_id &&
            orderItem.warehouse != ""
        );

        item["warehouse"] = orderItem
          ? orderItem.warehouse
          : selectedWarehouseForBulk;
      })
    );
    return selectedOrdersToStamp;
  }
  const checkItemWarehouse = (selectedOrdersToCheck) => {
    let itemsWithNoWarehouse = selectedOrdersToCheck
      .map((order) => {
        return order.current_line_items.map((item) => {
          return orderItemWarehouse.filter(
            (orderItem) =>
              orderItem.orderId == order.id &&
              orderItem.itemId == item.variant_id &&
              orderItem.warehouse == ""
          );
        });
      })
      .flat(2);

    if (itemsWithNoWarehouse.length > 0) return false;
    else return true;
  }
  const fulfill = async (selectedOrdersIds) => {
    closeModal();

    log("fulfill 1: ", selectedOrdersIds)

    let ordersAreReady = selectedOrdersIds.every((orderId) =>
      validateOrder(orderId)
    );


    if (selectedOrdersIds.length && ordersAreReady) {

      setProcessing(true);
      setSelectedOrdersNotReady(false);
      setCurrentlyFulfilledOrder(0);
      setTotalOrdersToFulfilling(selectedOrdersIds.length);

      let selectedOrdersToFulfill = selectedOrdersIds.map(orderId => {
        return orders.find(order => order.id == orderId)
      });

      log("fulfill 2: ", selectedOrdersToFulfill)

      selectedOrdersToFulfill = stampWarehouseToItem(selectedOrdersToFulfill);

      log("fulfill 3: ", selectedOrdersToFulfill)
      let result = await fulfillOrders(
        selectedOrdersToFulfill,
        orderItemWarehouse
      );

      setFailedToFetchZones(false);

      if (result.status == "success") {

        console.log(result)

        // let markResult = []

        for (let index = 0; index < selectedOrdersToFulfill.length; index++) {
          console.log(`barcode after fulfillment ${result.Barcodes}`);
          let res = await markOrderAsFulfilled(selectedOrdersToFulfill[index], result.Barcodes);

          // markResult.push(res);

          setCurrentlyFulfilledOrder(index + 1);
          forceUpdate();
          console.log(res);

        }

        let barcodeList = result.Barcodes.map(tuple => tuple.Item2)

        let awbResult = await getAWB(barcodeList);

        if (awbResult.status == "success") {

          setFulfillmentResult({
            isFulfillmentRequested: true,
            isError: false,
            Message: awbResult.Message,
            AWB: awbResult.AWB,
          });
          await loadOrders("", true);


        } else {

          setFulfillmentResult({
            isFulfillmentRequested: true,
            isError: true,
            Message: awbResult.Message,
            AWB: null,
          })

        }

      } else {
        setFulfillmentResult({
          isFulfillmentRequested: true,
          isError: true,
          Message: result.Message,
          AWB: null,
        });
      }

      setProcessing(false);
      setCurrentlyFulfilledOrder(0);
      setTotalOrdersToFulfilling(0);

    } else {

      setSelectedOrdersNotReady(true);

    }
  }
  const log = (methodname, object) => {
    console.log(methodname + " :");
    console.log(object);
  }

  return (
    <div>
      {processing ? (
        <div>
          <ProgressBar progress={(currentlyFulfilledOrder / totalOrdersToFulfilling) * 100} />
          Fulfilled Orders: {currentlyFulfilledOrder} / {totalOrdersToFulfilling}
        </div>
      ) : (
        <div></div>
      )}
      {fulfillmentResult.isFulfillmentRequested ? (
        <div>

          {fulfillmentResult.isError ? (
            <Banner title="Something Went Wrong..." status="critical">
              <p> {fulfillmentResult.Message} </p>
            </Banner>
          ) : (
            <Banner
              title={fulfillmentResult.Message}
              status="success"
              action={{
                content: "Print AWB",
                onAction: () => {
                  reactNavigate("/pdf", { state: { awbList: fulfillmentResult.AWB } });
                },
              }}
            ></Banner>
          )}
        </div>
      ) : (
        <div> </div>
      )}
      <Card>

        {failedToFetchZones ? (
          <InlineError message="Some Zones couldn't be recognized, please select zones manually" />
        ) : (
          <div> </div>
        )}
        {selectedOrdersNotReady ? (
          <InlineError message="Some Orders are not ready for shipment" />
        ) : (
          <div> </div>
        )}
        <Button
          plain
          onClick={() => loadOrders(nextPageUrl, false)}
        >
          Load More{" "}
        </Button>
        <ResourceList
          resourceName={{ singular: "order", plural: "orders" }}
          items={orders.map((order) => {
            return {
              id: order.id,
              url: `/order/${order.id}`,
              name: order.name,
              created_at: order.created_at,
              current_total_price: order.current_total_price,
              total_outstanding: order.total_outstanding,
              line_items: order.line_items,
              shipping_address: order.shipping_address,
              tags: order.tags,
              refunds: order.refunds,
              current_line_items: order.current_line_items
            };
          })}
          selectedItems={selectedOrders}
          promotedBulkActions={[
            {
              content: "Fulfill Orders",
              disabled: processing,
              onAction: async () => {
                let selectedOrdersIds = selectedOrders;

                let selectedOrdersToStartFulfill = selectedOrdersIds.map(orderId => {
                  return orders.find(order => order.id == orderId)
                });

                await startFulfillmentProcess(selectedOrdersToStartFulfill);
              },
            },
          ]}
          onSelectionChange={setSelectedOrdersAndUpdateOrderItemWarehouse}
          renderItem={(item) => {
            const {
              id,
              url,
              name,
              created_at,
              current_total_price,
              total_outstanding,
              line_items,
              shipping_address,
              tags,
              refunds,
              current_line_items
            } = item;
            const { address1 } = shipping_address
              ? shipping_address
              : { address1: "" };

            // const refunded_line_items = refunds
            // .map((refund) =>refund.refund_line_items).flat(2);


            // let current_line_items = line_items.filter((line_item) => {
            //     let refunded_line_item = refunded_line_items.find(refund_item=>refund_item.line_item_id == line_item.id);
            //     if(refunded_line_item && refunded_line_item.quantity == line_item.quantity){
            //       return false
            //     }
            //     return true;
            //   }
            // ).map(line_item=>{
            //   let refunded_line_item = refunded_line_items.find(refund_item=>refund_item.line_item_id == line_item.id);
            //   if(refunded_line_item){
            //     line_item["quantity"] = line_item.quantity - refunded_line_item.quantity;
            //     return line_item
            //   }
            //   return line_item;
            // });
            // current_line_items = [];

            // log(name,current_line_items);


            return (
              <ResourceItem id={id}>
                <Stack vertical>
                  <Stack>
                    <Stack.Item>
                      <Button
                        plain
                        onClick={(e) => {
                          viewOrderDetails(url);
                        }}
                      >
                        <Heading> Order {name} </Heading>
                      </Button>
                    </Stack.Item>
                    <Stack.Item>
                      <TextStyle>
                        {format(new Date(created_at), "dd/MM/yyyy p")}
                      </TextStyle>
                    </Stack.Item>
                    <Stack.Item fill>
                      <TextStyle>
                        {total_outstanding}
                      </TextStyle>
                    </Stack.Item>
                    {failedToFetchZones &&
                      previousFailedOrder.includes(id) ? (
                      <Stack>
                        <Stack.Item>
                          <Select
                            id={id}
                            options={citiesOptions}
                            onChange={(e) => selectCity(e, id)}
                            value={
                              selectedCities[id]
                                ? selectedCities[id]
                                : ""
                            }
                            placeholder="Select City"
                          />
                        </Stack.Item>
                        <Stack.Item>
                          <Select
                            id={id}
                            disabled={!selectedNeighborhood[id].isCitySelected}
                            options={selectedNeighborhood[id].neighborhoodOptions}
                            onChange={(e) => selectNeighborhood(e, id)}
                            value={
                              selectedNeighborhood[id].neighborhood
                                ? selectedNeighborhood[id]
                                  .neighborhood
                                : ""
                            }
                            placeholder="Select Zone"
                          />
                        </Stack.Item>
                      </Stack>
                    ) : (
                      <div> </div>
                    )}
                    <Stack.Item>
                      {validateOrder(id) ? (
                        <Badge status="success">Ready</Badge>
                      ) : (
                        <Stack vertical>
                          <Badge status="critical">Not Ready</Badge>
                          <InlineError
                            message={
                              selectedNeighborhood[id]
                                ?.readyForShipmentMessage
                            }
                          />
                        </Stack>
                      )}
                    </Stack.Item>
                    <Stack.Item>
                      <Button
                        primary
                        onClick={() => fulfillByyMylerz(id)}
                      >

                        Fulfill by Mylerz
                      </Button>
                    </Stack.Item>
                  </Stack>
                  <Stack>
                    <Stack.Item fill>
                      <TextStyle> {address1} </TextStyle>
                    </Stack.Item>
                  </Stack>
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
          loading={processing}
          filterControl={
            <Filters
              queryValue={queryValue}
              queryPlaceholder="Filter Orders"
              filters={[]}
              onQueryChange={handleFiltersQueryChange}
              onQueryClear={handleQueryValueRemove}
              onClearAll={handleFiltersClearAll}
            />
          }
          hasMoreItems
        ></ResourceList>
        <Button
          plain
          onClick={() => loadOrders(nextPageUrl, false)}
        >
          Load More
        </Button>
      </Card>
      <Modal
        open={activeModal}
        onClose={() => closeModal()}
        title="Select Warehouse"
        primaryAction={{
          content: "Fulfill",
          onAction: () => {
            fulfill(selectedOrders);
          },
        }}
        secondaryActions={[
          {
            content: "Close",
            onAction: () => closeModal(),
          },
        ]}
      >
        <Modal.Section>
          <Select
            options={warehouseOptions}
            onChange={(e) => {
              setSelectedWarehouseForBulk(e)
            }}
            value={selectedWarehouseForBulk}
          ></Select>
        </Modal.Section>
      </Modal>
    </div>
  );

}

export default OrderList;
