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


class ScanTemplateWebSpiderPaths(object):
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
        'boostrap': 'str',
        'excluded': 'str',
        'honor_robot_directives': 'bool'
    }

    attribute_map = {
        'boostrap': 'boostrap',
        'excluded': 'excluded',
        'honor_robot_directives': 'honorRobotDirectives'
    }

    def __init__(self, boostrap=None, excluded=None, honor_robot_directives=None):  # noqa: E501
        """ScanTemplateWebSpiderPaths - a model defined in Swagger"""  # noqa: E501

        self._boostrap = None
        self._excluded = None
        self._honor_robot_directives = None
        self.discriminator = None

        if boostrap is not None:
            self.boostrap = boostrap
        if excluded is not None:
            self.excluded = excluded
        if honor_robot_directives is not None:
            self.honor_robot_directives = honor_robot_directives

    @property
    def boostrap(self):
        """Gets the boostrap of this ScanTemplateWebSpiderPaths.  # noqa: E501

        Paths to bootstrap spidering with.  # noqa: E501

        :return: The boostrap of this ScanTemplateWebSpiderPaths.  # noqa: E501
        :rtype: str
        """
        return self._boostrap

    @boostrap.setter
    def boostrap(self, boostrap):
        """Sets the boostrap of this ScanTemplateWebSpiderPaths.

        Paths to bootstrap spidering with.  # noqa: E501

        :param boostrap: The boostrap of this ScanTemplateWebSpiderPaths.  # noqa: E501
        :type: str
        """

        self._boostrap = boostrap

    @property
    def excluded(self):
        """Gets the excluded of this ScanTemplateWebSpiderPaths.  # noqa: E501

        Paths excluded from spidering.  # noqa: E501

        :return: The excluded of this ScanTemplateWebSpiderPaths.  # noqa: E501
        :rtype: str
        """
        return self._excluded

    @excluded.setter
    def excluded(self, excluded):
        """Sets the excluded of this ScanTemplateWebSpiderPaths.

        Paths excluded from spidering.  # noqa: E501

        :param excluded: The excluded of this ScanTemplateWebSpiderPaths.  # noqa: E501
        :type: str
        """

        self._excluded = excluded

    @property
    def honor_robot_directives(self):
        """Gets the honor_robot_directives of this ScanTemplateWebSpiderPaths.  # noqa: E501

        Whether to honor robot directives.  # noqa: E501

        :return: The honor_robot_directives of this ScanTemplateWebSpiderPaths.  # noqa: E501
        :rtype: bool
        """
        return self._honor_robot_directives

    @honor_robot_directives.setter
    def honor_robot_directives(self, honor_robot_directives):
        """Sets the honor_robot_directives of this ScanTemplateWebSpiderPaths.

        Whether to honor robot directives.  # noqa: E501

        :param honor_robot_directives: The honor_robot_directives of this ScanTemplateWebSpiderPaths.  # noqa: E501
        :type: bool
        """

        self._honor_robot_directives = honor_robot_directives

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
        if issubclass(ScanTemplateWebSpiderPaths, dict):
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
        if not isinstance(other, ScanTemplateWebSpiderPaths):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other
