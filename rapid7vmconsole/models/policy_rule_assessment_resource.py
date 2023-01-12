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


class PolicyRuleAssessmentResource(object):
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
        'links': 'list[Link]',
        'total': 'int',
        'total_failed': 'int',
        'total_not_applicable': 'int',
        'total_passed': 'int',
        'unscored': 'int'
    }

    attribute_map = {
        'links': 'links',
        'total': 'total',
        'total_failed': 'totalFailed',
        'total_not_applicable': 'totalNotApplicable',
        'total_passed': 'totalPassed',
        'unscored': 'unscored'
    }

    def __init__(self, links=None, total=None, total_failed=None, total_not_applicable=None, total_passed=None, unscored=None):  # noqa: E501
        """PolicyRuleAssessmentResource - a model defined in Swagger"""  # noqa: E501

        self._links = None
        self._total = None
        self._total_failed = None
        self._total_not_applicable = None
        self._total_passed = None
        self._unscored = None
        self.discriminator = None

        if links is not None:
            self.links = links
        if total is not None:
            self.total = total
        if total_failed is not None:
            self.total_failed = total_failed
        if total_not_applicable is not None:
            self.total_not_applicable = total_not_applicable
        if total_passed is not None:
            self.total_passed = total_passed
        if unscored is not None:
            self.unscored = unscored

    @property
    def links(self):
        """Gets the links of this PolicyRuleAssessmentResource.  # noqa: E501

        Hypermedia links to corresponding or related resources.  # noqa: E501

        :return: The links of this PolicyRuleAssessmentResource.  # noqa: E501
        :rtype: list[Link]
        """
        return self._links

    @links.setter
    def links(self, links):
        """Sets the links of this PolicyRuleAssessmentResource.

        Hypermedia links to corresponding or related resources.  # noqa: E501

        :param links: The links of this PolicyRuleAssessmentResource.  # noqa: E501
        :type: list[Link]
        """

        self._links = links

    @property
    def total(self):
        """Gets the total of this PolicyRuleAssessmentResource.  # noqa: E501

        The total number of policy rules.  # noqa: E501

        :return: The total of this PolicyRuleAssessmentResource.  # noqa: E501
        :rtype: int
        """
        return self._total

    @total.setter
    def total(self, total):
        """Sets the total of this PolicyRuleAssessmentResource.

        The total number of policy rules.  # noqa: E501

        :param total: The total of this PolicyRuleAssessmentResource.  # noqa: E501
        :type: int
        """

        self._total = total

    @property
    def total_failed(self):
        """Gets the total_failed of this PolicyRuleAssessmentResource.  # noqa: E501

        The total number of policy rules that are not compliant against all assets.  # noqa: E501

        :return: The total_failed of this PolicyRuleAssessmentResource.  # noqa: E501
        :rtype: int
        """
        return self._total_failed

    @total_failed.setter
    def total_failed(self, total_failed):
        """Sets the total_failed of this PolicyRuleAssessmentResource.

        The total number of policy rules that are not compliant against all assets.  # noqa: E501

        :param total_failed: The total_failed of this PolicyRuleAssessmentResource.  # noqa: E501
        :type: int
        """

        self._total_failed = total_failed

    @property
    def total_not_applicable(self):
        """Gets the total_not_applicable of this PolicyRuleAssessmentResource.  # noqa: E501

        The total number of policy rules that are not applicable against all assets.  # noqa: E501

        :return: The total_not_applicable of this PolicyRuleAssessmentResource.  # noqa: E501
        :rtype: int
        """
        return self._total_not_applicable

    @total_not_applicable.setter
    def total_not_applicable(self, total_not_applicable):
        """Sets the total_not_applicable of this PolicyRuleAssessmentResource.

        The total number of policy rules that are not applicable against all assets.  # noqa: E501

        :param total_not_applicable: The total_not_applicable of this PolicyRuleAssessmentResource.  # noqa: E501
        :type: int
        """

        self._total_not_applicable = total_not_applicable

    @property
    def total_passed(self):
        """Gets the total_passed of this PolicyRuleAssessmentResource.  # noqa: E501

        The total number of policy rules that are compliant against all assets.  # noqa: E501

        :return: The total_passed of this PolicyRuleAssessmentResource.  # noqa: E501
        :rtype: int
        """
        return self._total_passed

    @total_passed.setter
    def total_passed(self, total_passed):
        """Sets the total_passed of this PolicyRuleAssessmentResource.

        The total number of policy rules that are compliant against all assets.  # noqa: E501

        :param total_passed: The total_passed of this PolicyRuleAssessmentResource.  # noqa: E501
        :type: int
        """

        self._total_passed = total_passed

    @property
    def unscored(self):
        """Gets the unscored of this PolicyRuleAssessmentResource.  # noqa: E501

        The total number of policy rules that have a role of `\"unscored\"`.  # noqa: E501

        :return: The unscored of this PolicyRuleAssessmentResource.  # noqa: E501
        :rtype: int
        """
        return self._unscored

    @unscored.setter
    def unscored(self, unscored):
        """Sets the unscored of this PolicyRuleAssessmentResource.

        The total number of policy rules that have a role of `\"unscored\"`.  # noqa: E501

        :param unscored: The unscored of this PolicyRuleAssessmentResource.  # noqa: E501
        :type: int
        """

        self._unscored = unscored

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
        if issubclass(PolicyRuleAssessmentResource, dict):
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
        if not isinstance(other, PolicyRuleAssessmentResource):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other