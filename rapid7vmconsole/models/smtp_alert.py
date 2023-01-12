# coding: utf-8

"""
    Python InsightVM API Client

    OpenAPI spec version: 3
    Contact: support@rapid7.com
    Generated by: https://github.com/swagger-api/swagger-codegen.git
"""


import pprint
import re  # noqa: F401

import six


class SmtpAlert(object):
    """NOTE: This class is auto generated by the swagger code generator program.

    Do not edit the class manually.
    """

    """
    Attributes:
      swagger_types (dict): The key is attribute name
                            and the value is attribute type.
      attribute_map (dict): The key is attribute name
                            and the value is json key in definition.
    """
    swagger_types = {
        'enabled': 'bool',
        'enabled_scan_events': 'ScanEvents',
        'enabled_vulnerability_events': 'VulnerabilityEvents',
        'id': 'int',
        'limit_alert_text': 'bool',
        'links': 'list[Link]',
        'maximum_alerts': 'int',
        'name': 'str',
        'notification': 'str',
        'recipients': 'list[str]',
        'relay_server': 'str',
        'sender_email_address': 'str'
    }

    attribute_map = {
        'enabled': 'enabled',
        'enabled_scan_events': 'enabledScanEvents',
        'enabled_vulnerability_events': 'enabledVulnerabilityEvents',
        'id': 'id',
        'limit_alert_text': 'limitAlertText',
        'links': 'links',
        'maximum_alerts': 'maximumAlerts',
        'name': 'name',
        'notification': 'notification',
        'recipients': 'recipients',
        'relay_server': 'relayServer',
        'sender_email_address': 'senderEmailAddress'
    }

    def __init__(self, enabled=None, enabled_scan_events=None, enabled_vulnerability_events=None, id=None, limit_alert_text=None, links=None, maximum_alerts=None, name=None, notification=None, recipients=None, relay_server=None, sender_email_address=None):  # noqa: E501
        """SmtpAlert - a model defined in Swagger"""  # noqa: E501

        self._enabled = None
        self._enabled_scan_events = None
        self._enabled_vulnerability_events = None
        self._id = None
        self._limit_alert_text = None
        self._links = None
        self._maximum_alerts = None
        self._name = None
        self._notification = None
        self._recipients = None
        self._relay_server = None
        self._sender_email_address = None
        self.discriminator = None

        self.enabled = enabled
        if enabled_scan_events is not None:
            self.enabled_scan_events = enabled_scan_events
        if enabled_vulnerability_events is not None:
            self.enabled_vulnerability_events = enabled_vulnerability_events
        if id is not None:
            self.id = id
        if limit_alert_text is not None:
            self.limit_alert_text = limit_alert_text
        if links is not None:
            self.links = links
        if maximum_alerts is not None:
            self.maximum_alerts = maximum_alerts
        self.name = name
        self.notification = notification
        self.recipients = recipients
        self.relay_server = relay_server
        if sender_email_address is not None:
            self.sender_email_address = sender_email_address

    @property
    def enabled(self):
        """Gets the enabled of this SmtpAlert.  # noqa: E501

        Flag indicating the alert is enabled.  # noqa: E501

        :return: The enabled of this SmtpAlert.  # noqa: E501
        :rtype: bool
        """
        return self._enabled

    @enabled.setter
    def enabled(self, enabled):
        """Sets the enabled of this SmtpAlert.

        Flag indicating the alert is enabled.  # noqa: E501

        :param enabled: The enabled of this SmtpAlert.  # noqa: E501
        :type: bool
        """
        if enabled is None:
            raise ValueError("Invalid value for `enabled`, must not be `None`")  # noqa: E501

        self._enabled = enabled

    @property
    def enabled_scan_events(self):
        """Gets the enabled_scan_events of this SmtpAlert.  # noqa: E501

        Allows the user to specify which scan events generate an alert. Default values will be chosen if property is not specified as apart of the request. The default values are documented in the properties of `enabledScanEvents`.  # noqa: E501

        :return: The enabled_scan_events of this SmtpAlert.  # noqa: E501
        :rtype: ScanEvents
        """
        return self._enabled_scan_events

    @enabled_scan_events.setter
    def enabled_scan_events(self, enabled_scan_events):
        """Sets the enabled_scan_events of this SmtpAlert.

        Allows the user to specify which scan events generate an alert. Default values will be chosen if property is not specified as apart of the request. The default values are documented in the properties of `enabledScanEvents`.  # noqa: E501

        :param enabled_scan_events: The enabled_scan_events of this SmtpAlert.  # noqa: E501
        :type: ScanEvents
        """

        self._enabled_scan_events = enabled_scan_events

    @property
    def enabled_vulnerability_events(self):
        """Gets the enabled_vulnerability_events of this SmtpAlert.  # noqa: E501

        Allows the user to specify which vulnerability result events generate an alert. Default values will be chosen if property is not specified as apart of the request. The default values are documented in the properties of `enabledVulnerabilityEvents`.  # noqa: E501

        :return: The enabled_vulnerability_events of this SmtpAlert.  # noqa: E501
        :rtype: VulnerabilityEvents
        """
        return self._enabled_vulnerability_events

    @enabled_vulnerability_events.setter
    def enabled_vulnerability_events(self, enabled_vulnerability_events):
        """Sets the enabled_vulnerability_events of this SmtpAlert.

        Allows the user to specify which vulnerability result events generate an alert. Default values will be chosen if property is not specified as apart of the request. The default values are documented in the properties of `enabledVulnerabilityEvents`.  # noqa: E501

        :param enabled_vulnerability_events: The enabled_vulnerability_events of this SmtpAlert.  # noqa: E501
        :type: VulnerabilityEvents
        """

        self._enabled_vulnerability_events = enabled_vulnerability_events

    @property
    def id(self):
        """Gets the id of this SmtpAlert.  # noqa: E501

        The identifier of the alert.  # noqa: E501

        :return: The id of this SmtpAlert.  # noqa: E501
        :rtype: int
        """
        return self._id

    @id.setter
    def id(self, id):
        """Sets the id of this SmtpAlert.

        The identifier of the alert.  # noqa: E501

        :param id: The id of this SmtpAlert.  # noqa: E501
        :type: int
        """

        self._id = id

    @property
    def limit_alert_text(self):
        """Gets the limit_alert_text of this SmtpAlert.  # noqa: E501

        Reports basic information in the alert, if enabled.  # noqa: E501

        :return: The limit_alert_text of this SmtpAlert.  # noqa: E501
        :rtype: bool
        """
        return self._limit_alert_text

    @limit_alert_text.setter
    def limit_alert_text(self, limit_alert_text):
        """Sets the limit_alert_text of this SmtpAlert.

        Reports basic information in the alert, if enabled.  # noqa: E501

        :param limit_alert_text: The limit_alert_text of this SmtpAlert.  # noqa: E501
        :type: bool
        """

        self._limit_alert_text = limit_alert_text

    @property
    def links(self):
        """Gets the links of this SmtpAlert.  # noqa: E501


        :return: The links of this SmtpAlert.  # noqa: E501
        :rtype: list[Link]
        """
        return self._links

    @links.setter
    def links(self, links):
        """Sets the links of this SmtpAlert.


        :param links: The links of this SmtpAlert.  # noqa: E501
        :type: list[Link]
        """

        self._links = links

    @property
    def maximum_alerts(self):
        """Gets the maximum_alerts of this SmtpAlert.  # noqa: E501

        The maximum number of alerts that will be issued. To disable maximum alerts, omit the property in the request or specify the property with a value of `null`.  # noqa: E501

        :return: The maximum_alerts of this SmtpAlert.  # noqa: E501
        :rtype: int
        """
        return self._maximum_alerts

    @maximum_alerts.setter
    def maximum_alerts(self, maximum_alerts):
        """Sets the maximum_alerts of this SmtpAlert.

        The maximum number of alerts that will be issued. To disable maximum alerts, omit the property in the request or specify the property with a value of `null`.  # noqa: E501

        :param maximum_alerts: The maximum_alerts of this SmtpAlert.  # noqa: E501
        :type: int
        """
        if maximum_alerts is not None and maximum_alerts < 1:  # noqa: E501
            raise ValueError("Invalid value for `maximum_alerts`, must be a value greater than or equal to `1`")  # noqa: E501

        self._maximum_alerts = maximum_alerts

    @property
    def name(self):
        """Gets the name of this SmtpAlert.  # noqa: E501

        The name of the alert.  # noqa: E501

        :return: The name of this SmtpAlert.  # noqa: E501
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """Sets the name of this SmtpAlert.

        The name of the alert.  # noqa: E501

        :param name: The name of this SmtpAlert.  # noqa: E501
        :type: str
        """
        if name is None:
            raise ValueError("Invalid value for `name`, must not be `None`")  # noqa: E501

        self._name = name

    @property
    def notification(self):
        """Gets the notification of this SmtpAlert.  # noqa: E501

        The type of alert.  # noqa: E501

        :return: The notification of this SmtpAlert.  # noqa: E501
        :rtype: str
        """
        return self._notification

    @notification.setter
    def notification(self, notification):
        """Sets the notification of this SmtpAlert.

        The type of alert.  # noqa: E501

        :param notification: The notification of this SmtpAlert.  # noqa: E501
        :type: str
        """
        if notification is None:
            raise ValueError("Invalid value for `notification`, must not be `None`")  # noqa: E501
        allowed_values = ["SMTP", "SNMP", "Syslog"]  # noqa: E501
        if notification not in allowed_values:
            raise ValueError(
                "Invalid value for `notification` ({0}), must be one of {1}"  # noqa: E501
                .format(notification, allowed_values)
            )

        self._notification = notification

    @property
    def recipients(self):
        """Gets the recipients of this SmtpAlert.  # noqa: E501

        The recipient list. At least one recipient must be specified. Each recipient must be a valid e-mail address.  # noqa: E501

        :return: The recipients of this SmtpAlert.  # noqa: E501
        :rtype: list[str]
        """
        return self._recipients

    @recipients.setter
    def recipients(self, recipients):
        """Sets the recipients of this SmtpAlert.

        The recipient list. At least one recipient must be specified. Each recipient must be a valid e-mail address.  # noqa: E501

        :param recipients: The recipients of this SmtpAlert.  # noqa: E501
        :type: list[str]
        """
        if recipients is None:
            raise ValueError("Invalid value for `recipients`, must not be `None`")  # noqa: E501

        self._recipients = recipients

    @property
    def relay_server(self):
        """Gets the relay_server of this SmtpAlert.  # noqa: E501

        The SMTP server/relay to send messages through.  # noqa: E501

        :return: The relay_server of this SmtpAlert.  # noqa: E501
        :rtype: str
        """
        return self._relay_server

    @relay_server.setter
    def relay_server(self, relay_server):
        """Sets the relay_server of this SmtpAlert.

        The SMTP server/relay to send messages through.  # noqa: E501

        :param relay_server: The relay_server of this SmtpAlert.  # noqa: E501
        :type: str
        """
        if relay_server is None:
            raise ValueError("Invalid value for `relay_server`, must not be `None`")  # noqa: E501

        self._relay_server = relay_server

    @property
    def sender_email_address(self):
        """Gets the sender_email_address of this SmtpAlert.  # noqa: E501

        The sender e-mail address that will appear in the from field.  # noqa: E501

        :return: The sender_email_address of this SmtpAlert.  # noqa: E501
        :rtype: str
        """
        return self._sender_email_address

    @sender_email_address.setter
    def sender_email_address(self, sender_email_address):
        """Sets the sender_email_address of this SmtpAlert.

        The sender e-mail address that will appear in the from field.  # noqa: E501

        :param sender_email_address: The sender_email_address of this SmtpAlert.  # noqa: E501
        :type: str
        """

        self._sender_email_address = sender_email_address

    def to_dict(self):
        """Returns the model properties as a dict"""
        result = {}

        for attr, _ in six.iteritems(self.swagger_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value
        if issubclass(SmtpAlert, dict):
            for key, value in self.items():
                result[key] = value

        return result

    def to_str(self):
        """Returns the string representation of the model"""
        return pprint.pformat(self.to_dict())

    def __repr__(self):
        """For `print` and `pprint`"""
        return self.to_str()

    def __eq__(self, other):
        """Returns true if both objects are equal"""
        if not isinstance(other, SmtpAlert):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
